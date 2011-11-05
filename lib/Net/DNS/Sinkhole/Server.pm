# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s
package Net::DNS::Sinkhole::Server;
use parent qw(Net::DNS::Nameserver);
use Carp qw(croak);
use List::Util qw(first);

=head1 NAME

Net::DNS::Sinkhole::Server - a base class for pluggable resolver handlers

=head1 SYNOPSIS

  my $bl = Net::DNS::Sinkhole::Handler::Blacklist->new();
  $bl->trie->add_data("dyndns.org",{ records => {A => '* 86400 IN A 10.1.2.3'}});

  my $wl = Net::DNS::Sinkhole::Handler::Whitelist->new();
  $wl->trie->add("mtfnpy.org");

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

=cut

sub new { # {{{
  my ($class,%args) = @_;

  # Net::DNS::Nameserver->new will cluck and bail out if not passed a ReplyHandler that is a reference
  $self = $class->SUPER::new(%args, ReplyHandler => \1);

  # XXX This is poking at the innards of Net::DNS::Nameserver, XXX
  # XXX but I've got no other choice.                          XXX
  # Turn ReplyHandler from a subref into a ReplyHandler method call against ourself
  $self->{ReplyHandler} = sub { $self->ReplyHandler(@_) };

  croak "Blacklist resolver must be supplied to Sever->new()" unless ref($self->{BlackList});
  croak "Whitelist resolver must be supplied to Sever->new()" unless ref($self->{WhiteList});

  # Order of resolvers: Whitelist first, Blacklist second, Additional third.
  $self->{Resolvers} = [@$self{qw(WhiteList BlackList)},@{$self->{AdditionalResolvers}}];

  return $self;
} # }}}

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
    # return NXDOMAIN: because either the sinkhole/whitelist don't have the record
    # or the recursive resolver didn't find anything.
    $rcode = "NXDOMAIN";
  } # }}}

  # if our censorship check returns true, *and* we're learning,
  # we need to redo the lookup because it was wrong, and needs to be corrected.
  goto CENSOR_REDO if ( ($self->{AutoBlacklist} || $self->{AutoWhitelist} ) && $self->censor_authority(\@auth,\@add) );
  # XXX FIXME RGH: We need to censor auth/add for whitelisted individual records,
  # so the real auth/add records don't get leaked back to the client.
  return ( $rcode, \@ans, \@auth, \@add , $aa );

} # }}}


sub add_resolver { # {{{
  my ($self,@resolvers) = @_;
  push @{$self->{Resolvers}},@resolvers;
} # }}}

sub first_response { # {{{
  my ($self,$qname,$qtype,$qclass) = @_;
  foreach my $resolver (@{$self->{Resolvers}}) {
    my $answer = $resolver->send( $qname, $qtype, $qclass );
    return $answer if ($answer->header->rcode ne "IGNORE");
  }

  # fall through default
  return undef;
} # }}}


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

1;
