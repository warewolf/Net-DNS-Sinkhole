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
__END__

=head1 SYNOPSIS

 # create the DNS server
 my $server = Net::DNS::Sinkhole::Server->new(
     AutoWhitelist => 1,
     AutoBlacklist => 1,
     BlackList => $blacklist_resolver,
     WhiteList => $whitelist_resolver,
     AdditionalResolvers => [$recursive_resolver],
     LocalAddr=>[qw(127.0.0.1)],
     LocalPort=>5252,
     Verbose => 0,
 );

 # start the server
 $server->main_loop();

=head1 DESCRIPTION

This DNS sinkhole framework creates a DNS server that rewrites responses to queries using response handlers.  Common response handlers include but are not limited to: L<Blacklisting|Net::DNS::Sinkhole::Handler::Blacklist>, L<Whitelisting|Net::DNS::Sinkhole::Handler::Whitelist>, and L<Recursion|Net::DNS::Sinkhole::Handler::Recursive>.  Don't like how a stock response handler works?  Put your thoughts into code, make a new module a subclass of L<Net::DNS::Sinkhole::Handler>, and write a replacement C<handler()> routine.  Piece of 7-bit ascii cake.

=head1 OVERVIEW

=over 4

=item *

L<Net::DNS::Sinkhole> - this documentation

=item *

L<Net::DNS::Sinkhole::Server> - the nameserver class that responds to requests

=item *

L<Net::DNS::Sinkhole::Handler> - a base class for response handlers

=item *

L<Net::DNS::Sinkhole::Handler::Whitelist> - a whitelisting handler, from a static list of zones

=item *

L<Net::DNS::Sinkhole::Handler::Blacklist> - a blacklisting handler, from a static list of zones

=item *

L<Net::DNS::Sinkhole::Handler::Recursive> - a recursive DNS lookup handler

=item *

L<Net::DNS::Sinkhole::Resolver> - a resolver object that uses Handlers for resolution

=item *

L<Net::DNS::Sinkhole::Trie> - a subclass of L<Tree::Trie> tweaked for domain names

=back

=head1 SERVER

L<Server|Net::DNS::Sinkhole::Server> is a subclass of L<Net::DNS::Nameserver>, and supports the same options passed to L<Net::DNS::Nameserver> L<-E<gt>new|Net::DNS::Nameserver/new>, with a couple additions, and one underhanded trick to make L<Net::DNS::Nameserver> support using an object as a L<ReplyHandler|Net::DNS::Nameserver/EXAMPLE> subref.

There I<is> a specific order that the L<handlers|Net::DNS::Sinkhole::Handler> are called within L<Server|Net::DNS::Sinkhole::Server>.  First the L<whitelist|Net::DNS::Sinkhole::Handler::Whitelist>, next the L<blacklist|Net::DNS::Sinkhole::Handler::Blacklist>, and finally any number of L<additional resolvers|/AdditionalResolvers>.  This is so that L<whitelists|Net::DNS::Sinkhole::Handler::Whitelist> take precedence over L<blacklists|Net::DNS::Sinkhole::Handler::Blacklist>.  The first resolver that returns a L<RCODE|Net::DNS::Header/rcode> of something other than C<IGNORE> is the response that gets sent to the client.

Great care is taken to prevent data in the L<ADDITIONAL|Net::DNS::Packet/additional> and L<AUTHORITY|Net::DNS::Packet/authority> fields of blacklisted/whitelisted responses getting returned to clients.  If a list of authorative nameservers for blacklisted/whitelisted zones were returned to a client, that client would "learn" that the sinkhole server is not the sole authorative nameserver for a blacklisted domain, and real responses from the real authorative nameservers could be leaked to the client.  That's kind-of against the point of a sinkhole.

B<NOTE:> Rewriting of L<ADDITIONAL|Net::DNS::Packet/additional> and L<AUTHORITY|Net::DNS::Packet/authority> fields is I<not> performed for L<additional resolvers|Net::DNS::Sinkhole::Server/AdditionalResolvers>.

=head1 RESPONSE HANDLERS

=over 4

=item Whitelist

The L<Whitelist|Net::DNS::Sinkhole::Handler::Whitelist> handler performs recursive lookups for zones that have been whitelisted in a L<Trie|Net::DNS::Sinkhole::Trie>, and removes the L<ADDITIONAL|Net::DNS::Packet/additional> and  L<AUTHORITY|Net::DNS::Packet/authority> portions of the response before sending it to a client.  If a zone is not whitelisted, the handler returns the C<IGNORE> L<RCODE|Net::DNS::Header/rcode>.

L<Whitelist|Net::DNS::Sinkhole::Handler::Whitelist> isn't a subclass of L<Net::DNS::Resolver>, but arguments passed to to L<Whitelist|Net::DNS::Sinkhole::Handler::Whitelist> L<-E<gt>new|Net::DNS::Sinkhole::Handler::Whitelist/new> will be passed directly to L<Net::DNS::Resolver> L<-E<gt>new|Net::DNS::Resolver/new> so that you can specify the nameservers to be used for recursion, for example. 

By default, L<Whitelist|Net::DNS::Sinkhole::Handler::Whitelist> configures the L<Net::DNS::Resolver> to be recursive, which can be overridden with C<recursive =E<gt> 0> passed to L<Whitelist|Net::DNS::Sinkhole::Handler::Whitelist> L<-E<gt>new|Net::DNS::Sinkhole::Handler::Whitelist/new>.

=item Blacklist

The L<Blacklist|Net::DNS::Sinkhole::Handler::Blacklist> handler first checks a L<Trie|Net::DNS::Sinkhole::Trie> to see if the zone is blacklisted.  If it is, it retrieves the L<Trie|Net::DNS::Sinkhole::Trie> value for that zone (a hashref), and checks if the desired RR type / record pair exists under a C<records> key.  If the desired RR type exists, it returns that record to the client.  L<Blacklist|Net::DNS::Sinkhole::Handler::Blacklist> also provides proper L<ADDITIONAL|Net::DNS::Packet/additional> and L<AUTHORITY|Net::DNS::Packet/authority> values in the response to the client, to keep it coming back to the sinkhole server in the future.  If a zone is not blacklisted, the handler returns the C<IGNORE> L<RCODE|Net::DNS::Header/rcode>.

=item Recursive

The L<Recursive|Net::DNS::Sinkhole::Handler::Recursive> handler 

=back

=head1 RESOLVER

L<Resolver|Net::DNS::Sinkhole::Resolver> is a subclass of L<Net::DNS::Resolver::Programmable>, but extends it a bit.  It overrides the C<send()> method to support returning L<ADDITIONAL|Net::DNS::Packet/additional> and L<AUTHORITY|Net::DNS::Packet/authority> fields, and enables the use of a resolver object similar to how L<resolver_code|Net::DNS::Resolver::Programmable/resolver_code> works, and is aptly named C<resolver_object>.

B<NOTE:> If you're familiar how L<resolver_code|Net::DNS::Resolver::Programmable/resolver_code> in L<Net::DNS::Resolver::Programmable> works, the return value convention has been changed in L<Net::DNS::Sinkhole::Resolver>, and more closely resembles the return value convention of L<ReplyHandler in Net::DNS::Nameserver|Net::DNS::Nameserver/EXAMPLE>.

=head1 TRIE

L<Trie|Net::DNS::Sinkhole::Trie> is a subclass of L<Tree::Trie>, but does some things to it in order to make storing DNS domain names case insensitive, and memory efficient.  Because of that, some of the features have been disabled.  But overall, it acts the same.

=cut
