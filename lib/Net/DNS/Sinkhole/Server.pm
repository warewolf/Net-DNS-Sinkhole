# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s
package Net::DNS::Sinkhole::Server;
use parent qw(Net::DNS::Nameserver);

=head1 NAME

Net::DNS::Sinkhole::Server - a base class for pluggable resolver handlers

=head1 SYNOPSIS

  my $ns = Net::DNS::Sinkhole::Server->new(
    Resolvers => @resolvers,
    AutoWhitelist => 1,
    AutoBlacklist => 1,
    LocalAddr=>[qw(127.0.0.1)],
    LocalPort=5252
  );
  $ns->main_loop();

=cut

sub new { # {{{
  my ($class,@args) = @_;
  my $self = {};
  bless $self,$class;
  my $reply_handler;
  $self = $self->SUPER::new(@args, ReplyHandler => $reply_handler);
  $reply_handler = sub { $self->ReplyHandler(@_) }
  return $self;
} # }}}

sub ReplyHandler { # {{{
  my ($self) = shift;
  my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
  my ( $rcode, @ans, @auth, @add, $aa );

  # send requet to various resolvers.
  CENSOR_REDO: my $response = first_response($qname, $qtype, $qclass, $self->{Resolvers});

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
  goto CENSOR_REDO if ( ($self->{AutoBlacklist} || $self->{AutoWhitelist}) && $self->censor_authority(\@auth,\@add) );
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

  foreach my $resolver (@$self{_resolvers}) {
    my $answer = $resolver->send( $qname, $qtype, $qclass );
    return $answer if ($answer->header->rcode ne "IGNORE");
  }

  # fall through default
  return undef;
} # }}}



1;
