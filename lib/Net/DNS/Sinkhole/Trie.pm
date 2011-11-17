package Net::DNS::Sinkhole::Trie;
use Carp qw(carp);
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
  my ($class,%args) = @_;

  # we're not replacing Tree::Trie's new, just .. enhancing it.
  # so our constructor is Tree::Trie's constructor.
  my $self = $class->SUPER::new(
    { %args,
      freeze_end_marker => 1,
      end_marker=>"",
      deepsearch=> "exact",
    }
  );
  bless $self, $class;

  # enable wildcard option
  $self->{_WILDCARD} = 1 if $args{wildcard};

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

  # we expect strings to be fed to us, not arrayrefs.
  carp("word reference encountered and ignored when expecting scalar string in add()") for grep { ref($_) } @args;

  # remove any references
  @args = grep { ! ref($_) } @args;

  # add wildcard, if enabled
  @args = map { ("*.$_",$_) } @args if ($self->{_WILDCARD});

  # quash lowercase, split on periods, reverse order, and make into an array reference.
  @args = map { [ reverse split( m/\./, lc($_) ) ] } @args;

  # We don't want to return arrayrefs, so convert them back into regular domain names.
  my @ret = map { join(".",reverse @$_) } $self->SUPER::add(@args);

  return wantarray ? @ret : scalar @ret;
} # }}}

sub add_all { # {{{
  my ($self,@trees) = @_;
  carp(sprintf("attempt to merge a possibly non-conforming format %s trie into a %s trie unsupported and ignored",ref($_),ref($self))) for grep { !$_->isa($self) } @trees;
  $self->SUPER::add_all(grep { $_->isa($self) } @trees );
} # }}}

sub add_data { # {{{
  my ($self,@args) = @_;

  if ($self->{_WILDCARD}) {
    my @wildcard;
    for (my $i = 0; $i < $#args; $i += 2) {
      push @wildcard, "*.".$args[$i], $args[$i+1];
    }
    push @args,@wildcard;
  }

  # quash keys lowercase, split on periods, reverse order, and make into an array reference.
  for (my $i = 0; $i < $#args; $i+=2) {
    if (ref($args[$i])) {
      carp("word reference encountered and ignored when expecting scalar string in add_data()");
      # remove those elements
      splice(@args,$i,2);
      $i-=2; next;
    }
    $args[$i] = [reverse split( m/\./,lc($args[$i]))];
  }

  my (@ret) = map { join(".",reverse @$_) } $self->SUPER::add_data(@args);

  wantarray ? @ret : scalar @ret;
} # }}}

sub remove { # {{{
  my ($self,@args) = @_;

  # we expect strings to be fed to us, not arrayrefs.
  carp("word reference encountered and ignored when expecting scalar string in remove()") for grep { ref($_) } @args;

  # remove any references
  @args = grep { ! ref($_) } @args;

  # add wildcard, if enabled
  @args = map { ("*.$_",$_) } @args if ($self->{_WILDCARD});;

  # quash lowercase, split on periods, and reverse order
  @args = map { [reverse split( m/\./,lc($_))] } @args;

  # We don't want to return arrayrefs, so convert them back into regular domain names.
  my @ret = map { join(".",reverse @$_) } $self->SUPER::remove(@args);

  wantarray ? @ret : scalar @ret;
} # }}}

sub delete_data {#{{{
  my ($self,@args) = @_;

  # add wildcard, if enabled
  @args = map { ("*.$_",$_) } @args if ($self->{_WILDCARD});;

  # quash lowercase, split on periods, and reverse order
  @args = map { [reverse split( m/\./,lc($_))] } @args;

  my @ret = map { join(".",reverse @$_) } $self->SUPER::delete_data(@args);

  wantarray ? @ret : scalar @ret;
}#}}}

sub lookup { # {{{
  my ($self,$word) = @_;
  $word = [reverse split( m/\./,lc($word))];

  # return value is variable based on list/scalar context
  if (wantarray) {
    my @ret = map { join(".",reverse @$_) } $self->SUPER::lookup($word);
    return @ret;
  } else {
    my $ret = $self->SUPER::lookup($word);
    return ref $ret ? join(".",reverse @$ret) : undef;
  }
} # }}}

sub lookup_data { # {{{
  my ($self,$word) = @_;
  $word = [reverse split( m/\./,lc($word))];
  $self->SUPER::lookup_data($word);
} # }}}

# No permission to change deepsearch.
sub deepsearch { # {{{
  my ($self) = @_;
  return $self->SUPER::deepsearch(4);
} # }}}

# No permission to change end_marker
sub end_marker { # {{{
  my ($self) = @_;
  $self->SUPER::end_marker("");
} # }}}

# no changes to freeze_end_marker
sub freeze_end_marker { # {{{
  my ($self) = @_;
  $self->SUPER::freeze_end_marker(1);
} # }}}

sub wildcard { # {{{
  my ($self,$option) = @_;
  if ($option) {
    $self->{_WILCARD} = $option;
  }
  return $self->{_WILDCARD};
} # }}}

1;
