# vim: foldmethod=marker filetype=perl sw=2 commentstring=\ #\ %s
package Net::DNS::Sinkhole::Resolver;
use parent qw(Net::DNS::Resolver::Programmable);

=head1 NAME

Net::DNS::Sinkhole::Resolver - a base class for pluggable resolver handlers

=head1 SYNOPSIS

my $whitelist_handler = Net::DNS::Sinkhole::Handler::Whitelist;
$whitelist_handler->trie->add("mtfnpy.com");
my $whitelist_resolver = Net::DNS::Sinkhole::Resolver->new(resolver_object => $whitelist_handler);

=cut

$Net::DNS::rcodesbyname{IGNORE} = 11;
%Net::DNS::rcodesbyval = reverse %Net::DNS::rcodesbyname;

# extend Net::DNS::Resolver::Programmable to support a resolver object
sub new { # {{{
    my ($self, %options) = @_;
    
    # Create new object:
    $self = $self->SUPER::new(%options);
    
    $self->{resolver_object} = $options{resolver_object};
    
    return $self;
} # }}}

sub resolver {
  my ($self) = @_;
  $self->{resolver_object};
}

# extend Net::DNS::Resolver::Programmable to support a resolver object
sub send { # {{{
    my $self = shift;

    my $query_packet = $self->make_query_packet(@_);
    my $question = ($query_packet->question)[0];
    my $domain   = lc($question->qname);
    my $rr_type  = $question->qtype;
    my $class    = $question->qclass;

    $self->_reset_errorstring;

    my ($rcode, $answer, $authority, $additional, $headermask );

    if (defined(my $resolver_code = $self->{resolver_code})) { # {{{
        ($rcode, $answer, $authority, $additional, $headermask ) = $resolver_code->($domain, $rr_type, $class);
    } # }}}

    if (defined(my $resolver_object = $self->{resolver_object})) { # {{{
        ($rcode, $answer, $authority, $additional, $headermask ) = $resolver_object->handler($domain, $rr_type, $class);
    } # }}}

    if (not defined($rcode) or defined($Net::DNS::rcodesbyname{$rcode})) { # {{{
        # Valid RCODE, return a packet:
        $rcode = 'NOERROR' if not defined($rcode);

        if (defined(my $records = $self->{records})) { # {{{
            if (ref(my $rrs_for_domain = $records->{$domain}) eq 'ARRAY') {
                foreach my $rr (@$rrs_for_domain) {
                    push(@$answer, $rr)
                        if  $rr->name  eq $domain
                        and $rr->type  eq $rr_type
                        and $rr->class eq $class;
                }
            }
        } # }}}

        my $reply = Net::DNS::Packet->new($domain, $rr_type, $class);
        $reply->header->qr(1); # query response
        $reply->header->rcode($rcode);
        $reply->push(question => $query_packet->question); # query section returned to caller (?)
        # fill in the response body
        $reply->push(answer => @$answer) if $answer;
        $reply->push(authority => @$authority) if $authority;
        $reply->push(additional => @$additional) if $additional;

        $reply->header->aa(1) if $headermask->{'aa'};
        $reply->header->ra(1) if $headermask->{'ra'};
        $reply->header->ad(1) if $headermask->{'ad'};

        return $reply;
    } # }}}
    else { # {{{
        # Invalid RCODE, signal error condition by not returning a packet:
        $self->errorstring($rcode);
        return undef;
    } # }}}
} # }}}

1;
