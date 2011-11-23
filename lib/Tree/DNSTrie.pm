# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s
package Tree::DNSTrie;
use strict;
use warnings;
use Carp qw(carp);
use List::Util qw(first);
use parent qw(Tree::Trie);

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

sub add { # {{{
  my ($self,@args) = @_;

  # we expect strings to be fed to us, not arrayrefs.
  carp("word reference encountered and ignored when expecting scalar string in add()") if first { ref($_) } @args;

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

# since we reorder data on insert, merging in Tree::Trie(s) that aren't a subclass of us makes little sense.
sub add_all { # {{{
  my ($self,@trees) = @_;
  my @valid_trees = grep { $_->isa($self) } @trees;
  $self->SUPER::add_all(@valid_trees);
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
  carp("word reference encountered and ignored when expecting scalar string in remove()") if first { ref($_) } @args;

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
