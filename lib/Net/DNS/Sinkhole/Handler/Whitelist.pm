# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s
package Net::DNS::Sinkhole::Handler::Whitelist;
use parent qw(Net::DNS::Sinkhole::Handler);
use strict;
use warnings;
use Net::DNS::Resolver;
use List::Util qw(first);

=head1 NAME

Net::DNS::Sinkhole::Handler::Whitelist - a whitelisting handler for a resolver

=head1 SYNOPSIS

my $whitelist_handler = Net::DNS::Sinkhole::Handler::Whitelist->new();

# add mtfnpy.com and *.mtfnpy.com to whitelist
$whitelist_handler->trie->add("mtfnpy.com");

=cut

sub new { # {{{
    my ($self, @args) = @_;

    # Create new object:
    $self = $self->SUPER::new(@args);

    # Whitelist handler needs a recursive resolver
    $self->{_recursive} =  Net::DNS::Resolver->new(recursive => 1,@args);

    return $self;
} # }}}

sub handler { # {{{
  my ( $self, $qname, $qtype, $qclass ) = @_;
  my ( $rcode, @answer, @authority, @additional, $headermask );

  my $zone = first { $self->trie->lookup($_) } $self->wildcardsearch($qname);
  # $zone might be undef if no responses
  if ($zone) { # response was found {{{
    my $answer = $self->{_recursive}->send( $qname, $qtype, $qclass );

    # clone the response
    $rcode        = $answer->header->rcode;
    @answer       = $answer->answer;
  } # }}}
  else { # no zone found in our trie, return custom rcode IGNORE {{{
    $rcode = "IGNORE";
  } # }}}

  return ( $rcode, \@answer, \@authority, \@additional, $headermask );
} # }}}

1;
