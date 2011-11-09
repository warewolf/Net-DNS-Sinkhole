# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s
package Net::DNS::Sinkhole::Server;
use parent qw(Net::DNS::Nameserver);
use Carp qw(croak);
use List::Util qw(first);

=head1 NAME

Net::DNS::Sinkhole::Server - a server for pluggable resolver handlers

=head1 SYNOPSIS

  my $ns = Net::DNS::Sinkhole::Server->new(
    AutoWhitelist => 1,
    AutoBlacklist => 1,
    BlackList => $bl,
    WhiteList => $wl,
    AdditionalResolvers => @resolvers,
    LocalAddr=>[qw(127.0.0.1)],
    LocalPort=>5252
  );

  $ns->main_loop();

=head1 DESCRIPTION

L<Server|Net::DNS::Sinkhole::Server> is a subclass of L<Net::DNS::Nameserver>, and supports the same options passed to L<Net::DNS::Nameserver> L<-E<gt>new|Net::DNS::Nameserver/new>, with a couple additions, and one underhanded trick to make L<Net::DNS::Nameserver> support using an object as a L<ReplyHandler|Net::DNS::Nameserver/EXAMPLE> code reference.

There I<is> a specific order that the L<handlers|Net::DNS::Sinkhole::Handler> are called within L<Server|Net::DNS::Sinkhole::Server>.  First the L<whitelist|Net::DNS::Sinkhole::Handler::Whitelist>, next the L<blacklist|Net::DNS::Sinkhole::Handler::Blacklist>, and finally any number of L<additional resolvers|Net::DNS::Sinkhole::Server/AdditionalResolvers>.  This is so that L<whitelists|Net::DNS::Sinkhole::Handler::Whitelist> take precedence over L<blacklists|Net::DNS::Sinkhole::Handler::Blacklist>.  The first resolver that returns a L<RCODE|Net::DNS::Header/rcode> of something other than C<L<IGNORE|Net::DNS::Sinkhole::Server/THE_IGNORE_RCODE>> is the response that gets sent to the client.

Great care is taken to prevent data in the L<ADDITIONAL|Net::DNS::Packet/additional> and L<AUTHORITY|Net::DNS::Packet/authority> fields of blacklisted/whitelisted responses getting returned to clients.  If a list of authorative nameservers for blacklisted/whitelisted zones were returned to a client, that client would "learn" that the sinkhole server is not the sole authorative nameserver for a blacklisted domain, and real responses from the real authorative nameservers could be leaked to the client.  That's kind-of against the point of a sinkhole.

B<NOTE:> Rewriting of L<ADDITIONAL|Net::DNS::Packet/additional> and L<AUTHORITY|Net::DNS::Packet/authority> fields is I<not> performed for L<additional resolvers|Net::DNS::Sinkhole::Server/AdditionalResolvers>.


=head1 METHODS

=head2 new

Beacuse L<Net::DNS::Sinkhole::Server> is a subclass of L<Net::DNS::Nameserver>, it supports all the attributes L<Net::DNS::Nameserver> supports, plus additions.

=over 4

=item AutoWhitelist

If you want L<Net::DNS::Sinkhole::Server> to automatically whitelist new zones discovered through recursion to be hosted by whitelisted nameservers, turn this on.  Any true value is enabled, any false value is disabled.  In other words, 1 is on, 0 is off.

=item AutoBlacklist

If you want L<Net::DNS::Sinkhole::Server> to automatically blacklist new zones discovered through recursion to be hosted by blacklisted nameservers, I<and> automatically blacklist new nameservers authorative for blacklisted zones, turn this on.  Any true value is enabled, any false value is disabled.  In other words, 1 is on, 0 is off.

=item BlackList

Specify your L<Resolver|Net::DNS::Sinkhole::Resolver> object here that contains a L<blacklist handler|Net::DNS::Sinkhole::Handler::Blacklist>.  Required.

=item WhiteList

Specify your L<Resolver|Net::DNS::Sinkhole::Resolver> object here that contains a L<whitelist handler|Net::DNS::Sinkhole::Handler::Whitelist>.  Required.

=item AdditionalResolvers

An array reference containing any number of L<resolver objects|Net::DNS::Sinkhole::Resolver> you like.  These will be called I<after> the  L<whitelist handler|Net::DNS::Sinkhole::Handler::Whitelist> and L<blacklist handler|Net::DNS::Sinkhole::Handler::Blacklist>.  If you want the L</AutoWhitelist> and L</AutoBlacklist> functionality to work, you need to provide a L<resolver object|Net::DNS::Sinkhole::Resolver> that has a L<recursive handler|Net::DNS::Sinkhole::Handler::Recursive> in it.  Optional, but strongly suggested.

=back

=cut

sub new { # {{{
  my ($class,%args) = @_;

  # Net::DNS::Nameserver->new will cluck and bail out if not passed a ReplyHandler that is a reference
  $self = $class->SUPER::new(%args, ReplyHandler => \1);

  # XXX This is poking at the innards of Net::DNS::Nameserver, XXX
  # XXX but I've got no other choice.                          XXX
  # Turn ReplyHandler from a subref into a ReplyHandler method call against our $self
  $self->{ReplyHandler} = sub { $self->ReplyHandler(@_) };

  croak "Blacklist resolver must be supplied to Sever->new()" unless ref($self->{BlackList});
  croak "Whitelist resolver must be supplied to Sever->new()" unless ref($self->{WhiteList});

  # Order of resolvers: Whitelist first, Blacklist second, Additional third.
  $self->{Resolvers} = [@$self{qw(WhiteList BlackList)},@{$self->{AdditionalResolvers}}];

  return $self;
} # }}}

=head2 ReplyHandler

ReplyHandler is what takes care of sending requests to the resolver objects, in order.  That order is the resolver object containing a L<whitelist|Net::DNS::Sinkhole::Handler::Whitelist> first, the resolver object containing a L<blacklist|Net::DNS::Sinkhole::Handler::Blacklist> second, and any additional resolvers third.  The L<first resolver to respond|/first_response> with an L<RCODE|Net::DNS::Header/rcode> other than C<L<IGNORE|Net::DNS::Sinkhole::Server/THE_IGNORE_RCODE>> wins, and that response is sent to the client.

ReplyHandler is a good subroutine to play with if you want logging of queries and responses.

=cut

sub ReplyHandler { # {{{
  my ($self) = shift;
  my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
  my ( $rcode, @ans, @auth, @add, $aa );

  # send requet to various resolvers.
  CENSOR_REDO: my $response = $self->first_response($qname, $qtype, $qclass);

  # $response might be undef if nothing responded
  if ($response) { # response was valid {{{
    $rcode = $response->header->rcode;
    @ans   = $response->answer;
    @add   = $response->additional;
    @auth  = $response->authority;
  } # }}}
  else { # none of our resolvers found anything {{{
    # return NXDOMAIN: because either the blacklist/whitelist don't have the record
    # or the recursive resolver didn't find anything.
    $rcode = "NXDOMAIN";
  } # }}}

  # if our censorship check returns true, *and* we're learning,
  # we need to redo the lookup because it was initially wrong, and needs to be corrected.
  goto CENSOR_REDO if ( ($self->{AutoBlacklist} || $self->{AutoWhitelist} ) && $self->censor_authority(\@auth,\@add) );

  return ( $rcode, \@ans, \@auth, \@add , $aa );

} # }}}

=head2 first_response

first_response is used internally by L<ReplyHandler|/ReplyHandler> to send requests to resolvers, and discontinues processing when it sees a resolver responded with a non-IGNORE RCODE.

=cut

sub first_response { # {{{
  my ($self,$qname,$qtype,$qclass) = @_;
  foreach my $resolver (@{$self->{Resolvers}}) {
    my $answer = $resolver->send( $qname, $qtype, $qclass );
    return $answer if ($answer->header->rcode ne "IGNORE");
  }

  # fall through default
  return undef;
} # }}}

=head2 censor_authority

censor_authority is where two primary features occur: the removal of the ADDITIONAL and AUTHORITY sections for query responses that are neither blacklisted or whitelisted, and automatic whitelisting and blacklisting.

censor_authority returns true in the event that something required automatic whitelisting or blacklisting, meaning that the query response was initially incorrect, and should be performed again by ReplyHandler

=cut

# censor authority & additional records
sub censor_authority { # {{{
  my ($self,$authority,$additional) = @_;

  foreach my $record (@$authority) { # {{{
    my @record_fields;

    # There's two types of records we get back in AUTHORITY sections.
    # NS and SOA.  But we treat them mostly the same.
    if ($record->type() eq 'NS')
    { @record_fields = qw(name nsdname); }

    elsif ($record->type() eq 'SOA')
    { @record_fields = qw(name mname); }

    my ($zone,$nameserver) = map { $record->$_() } @record_fields;

    # either the zone in $zone, or the nameserver in $nameserver could be something we're "authoritive" for.
    my $blacklisted_ns =  first { $self->{BlackList}->resolver->trie->lookup($_) } $self->{BlackList}->resolver->wildcardsearch($nameserver);
    my $blacklisted_zone = first { $self->{BlackList}->resolver->trie->lookup($_) } $self->{BlackList}->resolver->wildcardsearch($zone);

    my $whitelisted_ns = first { $self->{WhiteList}->resolver->trie->lookup($_) } $self->{WhiteList}->resolver->wildcardsearch($nameserver);
    my $whitelisted_zone = first { $self->{WhiteList}->resolver->trie->lookup($_) } $self->{WhiteList}->resolver->wildcardsearch($zone);

    if ($whitelisted_zone) { # {{{
      # zone is whitelisted
      if (! $whitelisted_ns) { # {{{
        # ... but nameserver is not.
        # We should fake out that we're the only authorative NS for the zone,
        # so that other (potentially blacklisted) zones hosted by this nameserver
        # are inaccessible by clients unless they go through us for sinkhole checking.
        print STDERR "Warning: zone $zone is whitelisted under $whitelisted_zone, but its nameserver $nameserver is not.\n" if ($self->{Verbose});
      } # }}}
      else { # {{{
        # ... and NS is whitelisted.
        # We're good.
        print STDERR "Info: zone $zone and ns $nameserver are both whitelisted.\n";
      } # }}}
    } # }}}
    else { # {{{
      # zone is not whitelisted
      if ( ! $whitelisted_ns ) { # {{{
        # ... and nameserver is not whitelisted
        # we should check sinkholes to see if the NS is blacklisted.
        print STDERR "Proceed carefully: zone $zone is not whitelisted, neither is its authorative NS $nameserver.  Sinkholes should be checked.\n" if ($self->{Verbose});
      } # }}}
      else { # {{{
        # ... but nameserver is whitelisted.
        # we should check sinkholes to see if the zone is blacklisted.
        print STDERR "Warning: zone $zone is not whitelisted, but authorative NS $nameserver is whitelisted under $whitelisted_ns.\n" if ($self->{Verbose});
        if ($self->{AutoWhitelist}) { # {{{
		  $self->{WhiteList}->resolver->trie->clone_record($whitelisted_ns,$zone);
          return 1;
        } # }}}
        # fall through to sinkhole ns/zone checking
      } # }}}
    } # }}}

    # if whitelisting had ANYTHING to do with the zone or nameserver, we should not have reached here.

    if ( $blacklisted_ns ) { # {{{
      if ( ! $blacklisted_zone) { # {{{
        # nameserver is blacklisted, but zoneis NOT blacklisted.
        # This is a new zone hosted by a blacklisted NS we don't know about.
        print STDERR "Critical: NS $nameserver in blacklisted zone $blacklisted_ns authorative for non-blacklisted (new?) zone $zone.\n" if ($self->{Verbose});
        if ($self->{AutoBlacklist}) { # {{{
          $self->{BlackList}->resolver->trie->clone_record($blacklisted_ns,$zone);
          return 1;
        } # }}}
      } # }}}
      else { # {{{
        # nameserver is blacklisted, and zone is blacklisted.
        # We're good.
        print STDERR "Info: NS $nameserver is is in blacklisted zone $blacklisted_ns and authorative for blacklisted zone $zone\n" if ($self->{Verbose});
      } # }}}
    } # }}}
    else { # {{{
      if ( $blacklisted_zone ) { # {{{
        # nameserver is NOT blacklisted, but zone is blacklisted.
        # This is a new nameserver that we don't know about, for a blacklisted zone.
        print STDERR "Critical: (new?) NS $nameserver is authorative for blacklisted zone $zone, but $nameserver isn't blacklisted.\n" if ($self->{Verbose});
        # XXX FIXME RGH: auto-sinkhole new nameserver?
        if ($self->{AutoBlacklist}) { # {{{
          $self->{BlackList}->resolver->trie->clone_record($blacklisted_zone,$nameserver);
          return 1;
        } # }}}
      } # }}}
      else { # {{{
        # nameserver is NOT blacklisted, and zone is NOT blacklisted.
        print STDERR "Info: NS $nameserver not blacklisted hosting non-blacklisted zone $zone. Why are we here?\n" if ($self->{Verbose});

        # Because we can't trust that these additional/authority records
        # will not conflict with a blacklisted zone, we really need to remove them.

        # kill the AUTHORITY records
        map { $_ = undef } @$authority;
        # kill the ADDITIONAL records
        map { $_ = undef } @$additional;
        return; # this is required, otherwise we'll try to iterate through undef objects above.
      } # }}}
    } # }}}
  } # }}}

  return;
} # }}}

=head1 THE IGNORE RCODE

The DNS specification (RFC1035) lists 10 L<RCODEs|Net::DNS::Header/rcode>, but has a block of 4 that are unassigned.  L<Net::DNS::Sinkhole::Server> and L<Net::DNS::Sinkhole::Handler> needed a way to communicate to each other to pass the message from Handler to Server "I'm not handling this DNS query, move on to the next handler".  So an unassigned L<RCODE|Net::DNS::Header/rcode> number 11 was used, and given the name IGNORE.  This is actually performed by L<Net::DNS::Sinkhole::Resolver> at runtime, adding the new L<RCODE|Net::DNS::Header/rcode> to a pair of L<Net::DNS> class data structures.

This L<RCODE|Net::DNS::Header/rcode> should never be seen by a client, since it is used solely internally by L<Net::DNS::Sinkhole::Server> and L<Net::DNS::Sinkhole::Handler>.  The only possible complication is if DNS suddenly decided to extend the L<RCODEs|Net::DNS::Header/rcode> further, into the currently unassigned block of 11 through 15.  It doesn't look like that is very likely, since other RFCs extend it up way beyond 15, but still leave 11-15 unassigned.

=cut

1;
