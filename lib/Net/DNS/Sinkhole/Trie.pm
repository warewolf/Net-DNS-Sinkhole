package Net::DNS::Sinkhole::Trie;
use Carp qw(croak);
use parent qw(Tree::Trie);
# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s

=head1 NAME

Net::DNS::Sinkhole::Store - a lightweight wrapper around Tree::Trie for storing DNS Domain names

=head1 SYNOPSIS

  use Net::DNS::Sinkhole::Trie;
  my $trie = Net::DNS::Sinkhole::Trie->new();

  # add example.com and *.example.com
  $trie->add('example.com');
  
=cut

use strict;
use warnings;
use Tree::Trie;

# enhance Tree::Trie's new to default to exact

sub new {  # {{{
  my ($class) = @_;
  my $self = Tree::Trie->new({deepsearch=> "exact"});
  bless $self, $class;
  return $self;
} # }}}

# wrap Tree::Trie's functions to reverse the inputs and outputs

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

sub add_all { my ($self) = @_; croak "add_all is unsupported"; }
sub remove { my ($self) = @_; croak "remove is unsupported"; }
sub delete_data { my ($self) = @_; croak "delete_data is unsupported"; }
sub deepsearch { my ($self) = @_; croak "deepsearch is unsupported"; }
sub end_marker { my ($self) = @_; croak "end_marker is unsupported"; }

### Custom subroutines

sub clone_record { # {{{
  my ($self,$source,$dest) = @_;
  my $data = $self->lookup_data($source);
  $self->add_data($dest, $data);
} # }}}


1;
