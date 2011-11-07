# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s
package Net::DNS::Sinkhole::Handler;
use Net::DNS::Sinkhole::Trie;
use strict;
use warnings;

=head1 NAME

Net::DNS::Sinkhole::Handler - a base handler and support functions

=head1 SYNOPSIS

=head1 METHODS

=head2 new

Create a new object.  No options.

=cut

sub new { # {{{
  my ($class) = @_;
  my $self = {};
  $self->{_trie} = Net::DNS::Sinkhole::Trie->new();
  bless $self,$class;
} # }}}

=head2 trie

Returns the L<trie|Net::DNS::Sinkhole::Trie> object contained in the Handler.

=cut

sub trie { # {{{
  my ($self) = @_;
  $self->{_trie};
} # }}}

=head2 wildcardsearch

Converts a domain name into a list of possible parent domain name wildcards that could match the domain name, progressivly getting less specific.  It will only produce wildcards down to a top level domain (e.g. "com").

Example: img1.srv.den.co.yahoo.com

Result: img1.srv.den.co.yahoo.com, *.srv.den.co.yahoo.com, *.den.co.yahoo.com, *.co.yahoo.com, *.yahoo.com, *.com

=cut

sub wildcardsearch { # {{{
  my ($self) = shift;
  my ($domain) = @_;
  my @parts = reverse( split( m/\./, $domain ) );
  my @wildcards = reverse map { join( ".", '*', reverse( @parts[ 0 .. $_ ] ), ) } 0 .. $#parts - 1;
  return $domain, @wildcards;
} # }}}

1;
