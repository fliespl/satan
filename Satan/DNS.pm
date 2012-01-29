#!/usr/bin/perl

## Satan::DNS
# Rootnode http://rootnode.net
#
# Copyright (C) 2009-2011 Marcin Hlybin
# All rights reserved.

package Satan::DNS;

use Satan::Tools qw(caps);
use IO::Socket;
use DBI;
use Data::Dumper;
use Crypt::GeneratePassword qw(chars);
use Data::Password qw(:all);
use feature 'switch';
use utf8;
use warnings;
use strict;

use Data::Validate::Domain qw(is_domain is_hostname);
use Data::Validate::IP qw(is_ipv4 is_ipv6);

use constant {
	DEFAULT_PRIO => 10,
	DEFAULT_TTL  => 300,
	SOA_SERIAL   => 666,
	SOA_REFRESH  => 10800, 
	SOA_RETRY    => 3600,  
	SOA_EXPIRE   => 604800,
	SOA_MIN_TTL  => 300
};

$|++;
$SIG{CHLD} = 'IGNORE';

sub new {
	my $class = shift;
	my $self = { @_	};
	my $dbh_system = $self->{dbh_system};

	$self->{dns_add_domain}      = $dbh_system->prepare("INSERT INTO domains(uid,name,type) VALUES(?,?,?)");
	$self->{dns_add_record}      = $dbh_system->prepare("INSERT INTO records(domain_id,name,type,content,ttl,prio,change_date) VALUES (?,?,?,?,?,?,UNIX_TIMESTAMP(NOW()))");
	$self->{dns_check_domain}    = $dbh_system->prepare("SELECT id,uid FROM domains WHERE name=?");
	$self->{dns_check_record}    = $dbh_system->prepare("SELECT id FROM records WHERE domain_id=? AND name=? AND type=? AND content=?");
	$self->{dns_check_record_id} = $dbh_system->prepare("SELECT r.id FROM records r INNER JOIN domains d ON r.domain_id = d.id WHERE r.id=? AND d.uid=?");   
	$self->{dns_del_domain}      = $dbh_system->prepare("DELETE FROM domains WHERE id=? AND uid=?");
	$self->{dns_del_record}      = $dbh_system->prepare("DELETE FROM records WHERE id=?");
	$self->{dns_list_domains}    = $dbh_system->prepare("
		SELECT 
			name,
			SUM(CASE type WHEN 'SOA'         THEN count ELSE 0 END) AS SOA,
			SUM(CASE type WHEN 'NS'          THEN count ELSE 0 END) AS NS,
			SUM(CASE type WHEN 'A' OR 'AAAA' THEN count ELSE 0 END) AS A, 
			SUM(CASE type WHEN 'CNAME'       THEN count ELSE 0 END) AS CNAME,
			SUM(CASE type WHEN 'MX'          THEN count ELSE 0 END) AS MX,
			SUM(CASE type WHEN 'TXT'         THEN count ELSE 0 END) AS TXT,
			SUM(CASE type WHEN 'SRV'         THEN count ELSE 0 END) AS SRV
			 
		FROM (
			SELECT d.name AS name,r.type AS type,count(r.type) AS count 
			FROM domains d LEFT JOIN records r ON d.id=r.domain_id 
			WHERE uid=?
			GROUP BY d.id,r.type
		) AS stats GROUP by name;
	");
	$self->{dns_list_records}    = $dbh_system->prepare("SELECT id, name, type, content, ttl, prio FROM records WHERE domain_id=?");
	
	#$self->{dns_limit} = $dbh_system->prepare("SELECT dns FROM limits WHERE uid=?");
	#$self->{event_add} = $dbh_system->prepare("INSERT INTO events(uid,date,daemon,event) VALUES(?,NOW(),'dns',?)");
	
	bless $self, $class;
	return $self;
}

sub add {
	my($self,@args) = @_;
	my $uid       = $self->{uid};
	my $login     = $self->{login};
	my $client    = $self->{client};

	my $dns_add_domain   = $self->{dns_add_domain};
	my $dns_add_record   = $self->{dns_add_record};
	my $dns_check_domain = $self->{dns_check_domain};
	my $dns_check_record = $self->{dns_check_record};

	my $domain_id;
	my $domain_name = shift @args or return "Not enough arguments! \033[1mDomain name\033[0m NOT specified. Please die or read help.";
	   $domain_name = lc $domain_name;
	is_domain($domain_name)       or return "Not good! \033[1m$domain_name\033[0m is NOT a proper domain name.";
	
	my $record_type = shift @args;
	$record_type = lc $record_type;
	
	# check if domain exists
	$dns_check_domain->execute($domain_name);
	if($dns_check_domain->rows) {
		($domain_id, my $domain_uid) = $dns_check_domain->fetchrow_array;
		if(not $record_type) {		
			if($domain_uid == $uid) {
				return "Domain \033[1m$domain_name\033[0m already added. Nothing to do.";
			} else {
				return "Cannot add domain! Domain \033[1m$domain_name\033[0m is owned by another user.";
			}
		}
	} else {
		# domain doesn't exist
		if(not $record_type) {
			# add domain
			$dns_add_domain->execute($uid,$domain_name,'NATIVE');
			return;
		} else {
			return "Domain \033[1m$domain_name\033[0m does NOT exist! Please double check the name or\n"
			     . "add the domain first with \033[1;32msatan dns add domain.com\033[0m command.";
		}
	}

	# subroutines for record type
	sub get_record_name {
		my($host_name,$domain_name) = @_;
		($host_name and $domain_name) or die "Not enough parameters in get_record_name sub.";

		my $record_name;
		if($host_name eq '@') {
			$record_name = $domain_name;
		} elsif($host_name eq '.') {
			$record_name = '*.'.$domain_name;
		} elsif(substr($host_name,0,1) eq '.') {
			$record_name = join('.', '*', substr($host_name,1), $domain_name);
		} else {
			$record_name = join('.', $host_name, $domain_name);
		}

		return $record_name;
	}
	
	sub check_host_name {
		my($host_name) = @_;
		($host_name) or die "Not enough parameters in check_host_name sub.";

		if($host_name eq '@' or $host_name eq '.') {
			# nothing to do
			return;
		} elsif(substr($host_name,0,1) eq '.') {
			# .host
			my $real_host_name = substr($host_name,1);
			is_hostname($real_host_name) or return "Host \033[1m$real_host_name\033[0m is NOT a proper host name.";
		} else {
			is_hostname($host_name) or return "Host \033[1m$host_name\033[0m is NOT a proper host name.";
		}
	
		return; # success
	}
	
	my($record_ttl, $record_prio) = (DEFAULT_TTL,undef);

	my $host_name = shift @args or return "Not enough arguments! \033[1mHost name\033[0m NOT specified. Please die or read help.";
	   $host_name = lc $host_name;
	my $check_host_name = &check_host_name($host_name);
	   $check_host_name and return $check_host_name;

	my $record_name = &get_record_name($host_name, $domain_name);
	my $record_content;

	given($record_type) {
		when(/^(a|aaaa)$/) {
			# satan dns add domain.com a <host|@|.> <IP>
			$record_content = shift @args or return "Not enough arguments! \033[1mIP address\033[0m NOT specified. Please die or read help.";
			$record_content = lc $record_content;
			if($record_type eq 'a') {
				is_ipv4($record_content) or return "Address \033[1m$record_content\033[0m is NOT a proper IPv4 address.";				
			} else {
				is_ipv6($record_content) or return "Address \033[1m$record_content\033[0m is NOT a proper IPv6 address.";
			}
		}
		when('cname') {
			# satan dns add domain.com cname <host> <domain>
			$record_content = shift @args or return "Not enough arguments! \033[1mIP address\033[0m NOT specified. Please die or read help.";
			$record_content = lc $record_content;
			is_hostname($record_content) or return "Domain \033[1m$record_content\033[0m is NOT a proper domain name.";
		}
		when('mx') {
			# satan dns add domain.com mx <host> <domain> <prio>
			$record_content = shift @args or return "Not enough arguments! \033[1mIP address\033[0m NOT specified. Please die or read help.";
			$record_content = lc $record_content;
			is_hostname($record_content) or return "Domain \033[1m$record_content\033[0m is NOT a proper domain name.";

			$record_prio = shift @args || DEFAULT_PRIO;
			$record_prio =~ /^([^0]\d*|0)$/ or return "Priority \033[1m$record_prio\033[0m must be a number! Try again.";
			$record_prio > 65535           and return "Priority \033[1m$record_prio\033[0m too high! Up in smoke.";
		}
		when('txt') {
			$record_content = shift @args or return "Not enough arguments! \033[1mText\033[0m NOT specified. Please die or read help.";
			length($record_content) > 255   and return "Text record too long! Only 255 chars possible.";
		}
		when('srv') {
			# satan dns add domain.com srv <host> <prio> <weight> <port> <domain>
			my($host_service, $host_proto) = $host_name =~ /^_(.+)\._(.+)$/; # split host name into <service> and <proto>
			($host_service and $host_proto) or return "Bad host name \033[1m$host_name\033[0m! Please use _<service>._<proto> host name.";
			is_hostname($host_service)             or return "Service \033[1m$host_service\033[0m is NOT a proper host name.";
			$host_proto =~ /^(tcp|udp)$/           or return "Bad protocol \033[1m$host_proto\033[0m. Only TCP and UDP is supported.";

			my $srv_prio = shift @args        or return "Not enough arguments! \033[1mPriority\033[0m NOT specified. Please die or read help.";
			   $srv_prio =~ /^([^0]\d*|0)$/   or return "Priority \033[1m$srv_prio\033[0m must be a number! Try again.";
			   $srv_prio > 65535             and return "Priority \033[1m$srv_prio\033[0m too high! Up in smoke.";

			my $srv_weight = shift @args      or return "Not enough arguments! \033[1mWeight\033[0m NOT specified. Please die or read help.";
			   $srv_weight =~ /^([^0]\d*|0)$/ or return "Weight \033[1m$srv_weight\033[0m must be a number! Try again.";
			   $srv_weight > 255             and return "Weight \033[1m$srv_weight\033[0m too high! Up in smoke.";

			my $srv_port = shift @args or return "Not enough arguments! \033[1mPort\033[0m NOT specified. Please die or read help.";
			   $srv_port =~ /^\d+$/    or return "Port \033[1m$srv_port\033[0m must be a number! Try againa.";
			 ( $srv_port < 1024 or $srv_port > 65535 ) and return "Port \033[1m$srv_port\033[0m must be between 1024 and 65535. Try again";
	
			my $srv_domain = shift @args or return "Not enough arguments! \033[1Domain\033[0m NOT specified. Please die or read help.";
			is_domain($srv_domain) or return "Domain \033[1m$srv_domain\033[0m is NOT a proper domain name.";

			$record_content = join(' ', $srv_prio, $srv_weight, $srv_port, $srv_domain);
		}
		when('soa') {
			# satan dns add domain.com soa <host> <ns> <mail>
			substr($host_name,0,1) eq '.' and return "Wildcard entry is not possible for SOA record.";

			my $soa_ns = shift @args or return "Not enough arguments! \033[1mNameserver\033[0m NOT specified. Please die or read help.";
			   $soa_ns = lc $soa_ns;
			is_domain($soa_ns) or return "Nameserver \033[1m$soa_ns\033[0m is NOT a proper domain name.";
		
			my $soa_mail = shift @args or return "Not enough arguments! \033[1mMail\033[0m NOT specified. Please die or read help.";
			   $soa_mail = lc $soa_mail;
			   $soa_mail =~ s/@/\./;
			is_domain($soa_mail) or return "Mail \033[1m$soa_mail\033[0m is NOT a proper domain name.";

			$record_content = join(' ', $soa_ns, $soa_mail, SOA_SERIAL, SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_MIN_TTL);
		}
		when(/^(ns|ptr)$/) {
			# satan dns add domain.com ns <host> <domain>
			substr($host_name,0,1) eq '.' and return "Wildcard entry is not possible for ".uc($record_type)." record.";

			$record_content = shift @args or return "Not enough arguments! \033[1mDomain\033[0m NOT specified. Please die or read help.";
			$record_content = lc $record_content;
			is_hostname($record_content) or return "Domain \033[1m$record_content\033[0m is NOT a proper domain name.";
		}
		default {
			return "Not good! \033[1m$record_type\033[0m is NOT a proper record type. See help.";
		}
	}

	@args > 0 and return "Too many arguments! See help.";	
	$record_type = uc $record_type;

	$dns_check_record->execute($domain_id,$record_name,$record_type,$record_content);
	if($dns_check_record->rows) {
		my($record_id) = $dns_check_record->fetchrow_array;
		#my $record_entry = join(' ', $record_name, uc($record_type), $record_content);
		return "Record \033[1m$record_id\033[0m already added. Nothing to do.";
	}

	$dns_add_record->execute($domain_id,$record_name,$record_type,$record_content,$record_ttl,$record_prio);
	return; # suckcess
}

sub del {
	my($self,@args) = @_;
        my $uid     = $self->{uid};
        my $login   = $self->{login};
        my $client  = $self->{client};
	
	my $dns_del_domain      = $self->{dns_del_domain};
	my $dns_del_record      = $self->{dns_del_record};
	my $dns_check_domain    = $self->{dns_check_domain};
	my $dns_check_record_id = $self->{dns_check_record_id};
	
	my $domain_id;
	my $domain_name = shift @args or return "Not enough arguments! \033[1mDomain name\033[0m or \033[1mrecord id\033[0m NOT specified. Please die or read help.";

	@args > 0 and return "Too many arguments! See help.";	

	if($domain_name =~ /^\d+$/) {
		# record id
		my $record_id = $domain_name;
		$dns_check_record_id->execute($record_id, $uid);
		if($dns_check_record_id->rows) {
			# record exists
			$dns_del_record->execute($record_id);
		} else {
			return "Record \033[1m$record_id\033[0m does NOT exist. Please double check the id.";
		}
	} else {
		# domain name
		is_domain($domain_name) or return "Domain \033[1m$domain_name\033[0m is NOT a proper domain name.";
		$dns_check_domain->execute($domain_name);
		if($dns_check_domain->rows) {
			($domain_id, my $domain_uid) = $dns_check_domain->fetchrow_array;
			if($domain_uid == $uid) {
				$dns_del_domain->execute($domain_id, $uid);
			} else {
				return "Domain \033[1m$domain_name\033[0m is NOT your domain! Cannot delete.";
			}
		} else {
			return "Domain \033[1m$domain_name\033[0m does NOT exist! Please double check the name.";
		}
	}
	
        #$event_add->execute($uid,"Deleted domain ($user)");

	return; #suckcess
}

sub list {
	my($self,@args) = @_;
        my $uid     = $self->{uid};
        my $login   = $self->{login};
        my $client  = $self->{client};

	my $dns_check_domain = $self->{dns_check_domain};
	my $dns_list_domains = $self->{dns_list_domains};
	my $dns_list_records = $self->{dns_list_records};
	
	my $domain_name = shift @args;
	@args > 0 and return "Too many arguments! See help.";	
	
	my $listing;
	if(not defined $domain_name) {	
		# list domains
		$dns_list_domains->execute($uid);
		$listing = Satan::Tools->listing(
			db      => $dns_list_domains,
			title   => "Domains",
			header  => ['Name','SOA','NS','A','CNAME','MX','TXT','SRV'],
			columns => [ qw(name SOA NS A CNAME MX TXT SRV) ],
		) || "No domains.";
	} else {
		$domain_name = lc $domain_name;
		is_domain($domain_name) or return "Domain \033[1m$domain_name\033[0m is NOT a proper domain name.";
	
		$dns_check_domain->execute($domain_name);
		if($dns_check_domain->rows) {
			my($domain_id, $domain_uid) = $dns_check_domain->fetchrow_array;
			if($domain_uid == $uid) {
				$dns_list_records->execute($domain_id);
				$listing = Satan::Tools->listing(
					db      => $dns_list_records,
					title   => "Domain $domain_name",
					header  => ['ID','Name','Type','Content','TTL','Priority'],
					columns => [ qw(id name type content ttl prio) ],
				) || "No domains.";
			} else {
				return "Domain \033[1m$domain_name\033[0m is NOT your domain! Cannot list.";
			}
		} else {
			return "Domain \033[1m$domain_name\033[0m does NOT exist! Please double check the name.";
		}
	}
	
	return $listing;
}


=mysql backend pdns

create table domains (
 id		 INT auto_increment,
 uid             SMALLINT UNSIGNED NOT NULL,
 name		 VARCHAR(255) UNIQUE NOT NULL,
 master		 VARCHAR(128) DEFAULT NULL,
 last_check	 INT DEFAULT NULL,
 type		 VARCHAR(6) NOT NULL,
 notified_serial INT DEFAULT NULL, 
 account         VARCHAR(40) DEFAULT NULL,
 primary key (id),
 KEY(uid),
 KEY(name)
) Engine=InnoDB;

CREATE TABLE records (
  id              INT auto_increment,
  domain_id       INT NOT NULL,
  name            VARCHAR(255) DEFAULT NULL,
  type            VARCHAR(10) DEFAULT NULL,
  content         VARCHAR(4096) DEFAULT NULL,
  ttl             INT DEFAULT 300,
  prio            INT DEFAULT NULL,
  change_date     INT DEFAULT NULL,
  primary key(id),
  KEY(name),
  KEY(name,type),
  KEY(domain_id),
  FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
)Engine=InnoDB;

create table supermasters (
  ip VARCHAR(25) NOT NULL, 
  nameserver VARCHAR(255) NOT NULL, 
  account VARCHAR(40) DEFAULT NULL
) Engine=InnoDB;

#GRANT SELECT ON supermasters TO pdns;
GRANT ALL ON domains TO pdns;
GRANT ALL ON records TO pdns;
=cut

1;