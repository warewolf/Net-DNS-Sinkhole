# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s
package Net::DNS::Sinkhole::Handler::Blacklist;
use parent qw(Net::DNS::Sinkhole::Handler);
use strict;
use warnings;
use List::Util qw(first);
use Net::DNS::RR;

sub handler { # {{{
  my ( $self, $qname, $qtype, $qclass ) = @_;
  my ( $rcode, @answer, @authority, @additional, $headermask );

  my $zone = first { $self->trie->lookup($_) } $self->wildcardsearch($qname);

  if ($zone) { # we found a record in our tree # {{{
    # grab the hashref that has our RR types & records
    my $record = $self->trie->lookup_data($zone);

    # check if the RR type we want exists
    if ( exists( $$record{records}{$qtype} ) ) { # RR exists, now we get to answer {{{
      # make our sinkholed response look like the question
      my $answer_rr = $record->{records}->{$qtype};
      $answer_rr =~ s/\*/$qname/g;
      # add the sinkholed RR to our answer section
      push @answer, Net::DNS::RR->new($answer_rr);

      # make a NS record for the authority section
      my $ns_rr = $record->{records}->{NS};
      $ns_rr =~ s/\*/$zone/g;
      # hide that we might be wildcarding stuff
      $ns_rr =~ s/^\*\.//g;
      # add the sinkholed NS to our authority section
      push @authority,Net::DNS::RR->new($ns_rr);

      # make an A record of the NS in the authority section for the additional section
      my $ns_name = $authority[0]->nsdname;

      # figure out what sinkholed "zone" the NS is in
      # XXX: this requires that the nameservers of sinkholed domains be in sinkholed domains!
      my $ns_zone = first { $self->trie->lookup($_) } $self->wildcardsearch($ns_name);
      # grab the records hashref for that zone
      my $ns_zone_records = $self->trie->lookup_data($ns_zone);
      # grab the A record in that hashref
      my $ns_a = $ns_zone_records->{records}->{A};
      # change the * to be the name of our nameserver
      $ns_a =~ s/\*/$ns_name/;
      # add the A record of our sinkholed NS to the additional section
      push @additional,Net::DNS::RR->new($ns_a);
      $rcode = "NOERROR";
    } # }}}
    else { # zone exists, but not the record we want. {{{
      $rcode = "NXDOMAIN";
    } # }}}
  } # }}}
  else { # we didn't find any records, so return custom rcode IGNORE {{{
    $rcode = "IGNORE";
  } # }}}
  return ( $rcode, \@answer, \@authority, \@additional, $headermask );
} # }}}

1;
