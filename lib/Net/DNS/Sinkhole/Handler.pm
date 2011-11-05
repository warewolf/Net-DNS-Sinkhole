# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s
package Net::DNS::Sinkhole::Handler;
use Net::DNS::Sinkhole::Trie;
use strict;
use warnings;

sub new { # {{{
  my ($class) = @_;
  my $self = {};
  $self->{_trie} = Net::DNS::Sinkhole::Trie->new();
  bless $self,$class;
} # }}}

sub trie { # {{{
  my ($self) = @_;
  $self->{_trie};
} # }}}

sub wildcardsearch { # {{{
  my ($self) = shift;
  my ($domain) = @_;
  my @parts = reverse( split( m/\./, $domain ) );
  my @wildcards = reverse map { join( ".", '*', reverse( @parts[ 0 .. $_ ] ), ) } 0 .. $#parts - 1;
  return $domain, @wildcards;
} # }}}

