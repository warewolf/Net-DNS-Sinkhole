# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s
package Net::DNS::Sinkhole::Handler::Recursive;
use parent qw(Net::DNS::Sinkhole::Handler);
use strict;
use warnings;
use Net::DNS::Resolver;
use List::Util qw(first);

=head1 NAME

Net::DNS::Sinkhole::Handler::Recursive - a recusing handler for a resolver

=head1 SYNOPSIS

my $recursive_handler = Net::DNS::Sinkhole::Handler::Recursive->new();

=head1 DESCRIPTION

=head1 METHODS

=head2 new

=cut

sub new { # {{{
    my ($self, @args) = @_;

    # Create new object:
    $self = $self->SUPER::new(@args);

    # Recursive handler needs a recursive resolver
    $self->{_recursive} =  Net::DNS::Resolver->new(recursive => 1,@args);

    return $self;
} # }}}

=head2 handler

=cut

sub handler { # {{{
  my ( $self, $qname, $qtype, $qclass ) = @_;
  my ( $rcode, @answer, @authority, @additional, $headermask );

  my $answer = $self->{_recursive}->send( $qname, $qtype, $qclass );

  # clone the response
  $rcode        = $answer->header->rcode;
  @answer       = $answer->answer;
  @additional   = $answer->additional;
  @authority    = $answer->authority;

  return ( $rcode, \@answer, \@authority, \@additional, $headermask );
} # }}}

1;
