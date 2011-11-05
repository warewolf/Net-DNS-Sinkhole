package Net::DNS::Sinkhole;
use strict;
use warnings;

use Net::DNS::Sinkhole::Trie;
use Net::DNS::Sinkhole::Handler;
use Net::DNS::Sinkhole::Server;
use Net::DNS::Sinkhole::Resolver;
use Net::DNS::Sinkhole::Handler::Blacklist;
use Net::DNS::Sinkhole::Handler::Recursive;
use Net::DNS::Sinkhole::Handler::Whitelist;


=head1 NAME

Net::DNS::Sinkhole - a sinkhole DNS server framework

=head1 VERSION

version 0.1

=cut

our $VERSION = '0.1';

1;
