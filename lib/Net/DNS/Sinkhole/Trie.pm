package Net::DNS::Sinkhole::Trie;
use Carp qw(croak);
use parent qw(Tree::Trie);
# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s

=head1 NAME

Net::DNS::Sinkhole::Trie - a lightweight wrapper around Tree::Trie for storing DNS Domain names

=head1 SYNOPSIS

  use Net::DNS::Sinkhole::Trie;
  my $trie = Net::DNS::Sinkhole::Trie->new();

  # add example.com and *.example.com
  $trie->add('example.com');
  
=cut

use strict;
use warnings;
use Tree::Trie;

=head1 DESCRIPTION

Net::DNS::Sinkhole::Trie is a subclass of L<Tree::Trie> customized for efficient storage of DNS domain names.  DNS has a hierarchy like a tree, but is expressed backwards.  This module takes care of quashing DNS names to lower case, and reverses the domain names at storage and retrieval time.

Instead of storing "www.google.com" where "www" would be the root, it is reversed so that the root is "com".  It actually ends up stored as moc.elgoog.www in the Trie.

Since this DNS sinkhole system is taking ownership of a portion of the DNS hierarchy, it makes sense to take ownership of that portion of the tree, and anything below it.  Example:

Add google.com:

  $trie->add("google.com");

This results in "google.com" being added to the trie, along with "*.google.com".  This is intentionally I<not> optional, because it will only lead to confusion of recursive nameservers that recurse into the sinkhole server for data, and headaches.

=head1 METHODS

=head2 new

Exactly the same as Tree::Trie ->new, but has been modified to change the deepsearch option to be "exact".

=cut

# enhance Tree::Trie's new to default to exact

sub new {  # {{{
  my ($class,@args) = @_;
  my $self = Tree::Trie->new({deepsearch=> "exact", @args});
  bless $self, $class;
  return $self;
} # }}}

### Custom subroutines

=head1 NEW METHODS

=head2 clone_record

clone_record() is used to copy the L<Trie|Net::DNS::Sinkhole::Trie> value from one key to another.  This is used in L<censor_authority|Net::DNS::Sinkhole::Server/censor_authority> during AutoWhitelisting and AutoBlacklisting.

Takes two arguments: source key to copy from, and destination key to copy to.

 $trie->clone_record($source_key,$destination_key);

=cut

sub clone_record { # {{{
  my ($self,$source,$dest) = @_;
  my $data = $self->lookup_data($source);
  $self->add_data($dest, $data);
} # }}}

=head1 MODIFIED METHODS

The following methods were modified in support of DNS name storage:

Modified to quash case to lower case, and reverse the input and output Trie keys.

=over 4

=item add

=item add_data

=item lookup

=item lookup_data

=back

=cut

sub add { # {{{
  my ($self,@args) = @_;

  # Tree::Trie supports adding an arrayref, but we don't.
  map { croak("Adding references is unsupported") if ref($_) } @args;

  # add *.zone.com when adding zone.com automatically
  my @wildcard = map { "*.$_" } @args;
  @args = (@wildcard,@args);

  my (@ret) = $self->SUPER::add(map { lc scalar reverse $_  } @args);
  @ret = map { scalar reverse lc($_) } @ret;
  wantarray ? @ret : scalar @ret;
} # }}}

sub add_data { # {{{
  my ($self,@args) = @_;
  my @wildcard;

  for (my $i = 0; $i < $#args; $i+=2) {
    $args[$i] = scalar reverse lc($args[$i]);
    # add *.zone.com when adding zone.com automatically
    push @wildcard,"$args[$i].*",$args[$i+1];
  }

  my (@ret) = $self->SUPER::add_data(@args,@wildcard);
  wantarray ? @ret : scalar @ret;
} # }}}

sub lookup { # {{{
  my ($self,@args) = @_;
  $args[0] = scalar reverse lc($args[0]);
  my (@ret) = $self->SUPER::lookup(@args);
  if (@ret) { $ret[0] = scalar reverse $ret[0]; }
} # }}}

sub lookup_data { # {{{
  my ($self,@args) = @_;
  $args[0] = scalar reverse lc($args[0]);
  $self->SUPER::lookup_data(@args);
} # }}}

### Subroutines I havn't wrapped yet

=head1 DISABLED METHODS

This method has been intentionally disabled, because they have not been implemented yet.

=over 4

=item remove

=item delete_data

=item deepsearch

=item end_marker

=back

=cut

sub add_all { my ($self) = @_; croak "add_all is unsupported"; }
sub remove { my ($self) = @_; croak "remove is unsupported"; }
sub delete_data { my ($self) = @_; croak "delete_data is unsupported"; }
sub deepsearch { my ($self) = @_; croak "deepsearch is unsupported"; }
sub end_marker { my ($self) = @_; croak "end_marker is unsupported"; }


1;
