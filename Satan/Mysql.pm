#!/usr/bin/perl
#
# Satan::MySQL
# Rootnode http://rootnode.net
#
# Copyright (C) 2009-2012 Marcin Hlybin
# All rights reserved.
#
package Satan::Mysql;

use warnings;
use strict;
use 5.010; # ~~ operator
use feature 'switch';
use utf8;
use FindBin qw($Bin);
use IO::Socket;
use DBI;
use Crypt::GeneratePassword qw(chars);
use Data::Password qw(:all);
use Data::Dumper;
#use Data::Validate::Domain qw(is_domain is_hostname);
#use Data::Validate::IP qw(is_ipv4 is_ipv6);

$|++;
#my $MINLEN = 8;   # password min length
#my $MAXLEN = 30;  # password max length
our $MINLEN = undef;
our $MAXLEN = undef;
$SIG{CHLD} = 'IGNORE';

sub new {
	my $class = shift;
	my ($self) = @_;
        my $dbh = DBI->connect("dbi:mysql:mysql;mysql_read_default_file=$Bin/../config/my.cnf",undef,undef,{ RaiseError => 0, AutoCommit => 1 });
	$dbh->{mysql_auto_reconnect} = 1;
	$dbh->{mysql_enable_utf8} = 1;

	my $db;
	$db->{check_db}   = $dbh->prepare("SHOW DATABASES LIKE ?");
	$db->{check_user} = $dbh->prepare("SELECT user FROM user WHERE user=?"); 
	$db->{add_user}   = $dbh->prepare("CREATE USER ? IDENTIFIED BY ?");
	$db->{del_user}   = $dbh->prepare("DROP USER ?");

	#$self->{dns_limit} = $dbh->prepare("SELECT dns FROM limits WHERE uid=?");
	#$self->{event_add} = $dbh->prepare("INSERT INTO events(uid,date,daemon,event) VALUES(?,NOW(),'dns',?)");
	$db->{get_users} = $dbh->prepare("SELECT user, host FROM user WHERE user like ?");
	

	$db->{get_db_grants}     = $dbh->prepare("SELECT * FROM db WHERE db LIKE ? ORDER BY Db, User, Host ASC");
	$db->{get_table_grants}  = $dbh->prepare("SELECT Host, Db, User, Table_name, Table_priv, Column_priv FROM tables_priv WHERE Db like ?");
	$db->{get_column_grants} = $dbh->prepare("SELECT Host, Db, User, Table_name, Column_name, Column_priv FROM columns_priv WHERE Db like ?");
	
	$db->{dbh} = $dbh;
	$self->{db} = $db;
	
	bless $self, $class;
	return $self;
}

sub add {
	my ($self, @args) = @_;
	my $uid = $self->{uid};
	my $db  = $self->{db};

	# database or user name
	my $name = shift @args or return "Not enough arguments! \033[1mDatabase name\033[0m NOT specified. Please die or read help.";
	   $name = lc $name;
	
	# add user command
	my $is_user;
	if ($name eq 'user') {
		$is_user = 1;
		$name = shift @args or return "Not enough arguments! \033[1mUser name\033[0m NOT specified. Please die or read help.";
		$name = lc $name;
	}
	
	# check user or database name		
	if ($name =~ /^(my${uid}_|)([a-z0-9]+)$/) {
		$name = $2;
	} 
	elsif ($name =~ /^my(\d+)_/) {
		return "ID \033[1m$1\033[0m in $name is different from your actual uid $uid.";
	}	
	else {
		return "Not good! \033[1m$name\033[0m is NOT a proper name. Only alphanumerics are allowed.";
	} 

	# real name is with prefix
	my $real_name = 'my'.$uid.'_'.$name;
	my $real_name_length = length($real_name);
	my $name_length = length($name);
	my $maximum_name_length = 16 - length('my'.$uid.'_');
	
	if ($name_length > $maximum_name_length) {
		my $name_type = $is_user ? "User" : "Database";
		return "$name_type name too long (\033[1m$name_length\033[0m chars). Maximum length is \033[1m$maximum_name_length\033[0m.";
	}
		
	# user or grant user password
	my $user_password = shift @args or return "Not enough parameters! \033[1mUser password\033[0m NOT specified.";
	my $bad_password_reason = IsBadPassword($user_password);
	if ($bad_password_reason) {
		return "Password too simple: $bad_password_reason.";
	}
	
	# add user
	if($is_user) {
		# check if user exists
		$db->{check_user}->execute($real_name);
		if ($db->{check_user}->rows) {
			return "User \033[1m$name\033[0m already added. Nothing to do.";
		}
		else {
			# add database
			$db->{add_user}->execute($real_name, $user_password) or return "Cannot add user \033[1m$real_name\033[0m. System error.";
		}
	}
	# add database
	else {
		# check if user exists
		$db->{check_user}->execute($real_name);
		if ($db->{check_user}->rows) {
			return "User \033[1m$name\033[0m exists. Cannot create grant user!";
		}

		# check if database exists
		$db->{check_db}->execute($real_name);
		if ($db->{check_db}->rows) {
			return "Database \033[1m$name\033[0m already added. Nothing to do.";
		} 
		else {
			# add database
			#$db->{add_db}->execute($real_name) or return "Cannot add database \033[1m$real_name\033[0m. System error.";
			$db->{dbh}->func('createdb', $real_name, 'admin') or return "Cannot add database \033[1m$real_name\033[0m. System error.";
			$db->{dbh}->do(qq{ GRANT ALL PRIVILEGES ON $real_name.* TO $real_name WITH GRANT OPTION })
				or return "Cannot set privileges to \033[1m$real_name\033[0m user. System error.";
		}
	}
	
	return;
}

sub del {
	my ($self, @args) = @_;
	my $uid = $self->{uid};
	my $db  = $self->{db};
	
	my $name = shift @args or return "Not enough arguments! \033[1mDatabase name\033[0m NOT specified. Please die or read help.";
	   $name = lc $name;
	
	# drop user command
	my $is_user;
	if ($name eq 'user') {
		$is_user = 1;
		$name = shift @args or return "Not enough arguments! \033[1mUser name\033[0m NOT specified. Please die or read help.";
		$name = lc $name;
	}
	
	# check user or database name		
	if ($name =~ /^(my${uid}_|)([a-z0-9]+)$/) {
		$name = $2;
	} 
	elsif ($name =~ /^my(\d+)_/) {
		return "ID \033[1m$1\033[0m in $name is different from your actual uid $uid.";
	}	
	else {
		return "Not good! \033[1m$name\033[0m is NOT a proper name. Only alphanumerics are allowed.";
	} 
	
	# real name is with prefix
	my $real_name = 'my'.$uid.'_'.$name;

	# delete user
	if ($is_user) {
		# check if user exists
		$db->{check_user}->execute($real_name);
		if ($db->{check_user}->rows) {
			# delete
			$db->{del_user}->execute($real_name) or return "Cannot delete user \033[1m$real_name\033[0m. System error.";
		}
		else {
			return "User \033[1m$name\033[0m does NOT exist.";
		}
	}
	# delete database
	else {
		# check if database exists
		$db->{check_db}->execute($real_name);
		if ($db->{check_db}->rows) {
			$db->{dbh}->func('dropdb', $real_name, 'admin') or return "Cannot delete database \033[1m$real_name\033[0m. System error.";
			$db->{del_user}->execute($real_name);
		} 
		else {
			# add database
			#$db->{add_db}->execute($real_name) or return "Cannot add database \033[1m$real_name\033[0m. System error.";
			return "Database \033[1m$name\033[0m does NOT exist.";
		}

	}
	
	return; 
}

sub list {
	my($self, @args) = @_;
	my $uid = $self->{uid};
	my $db  = $self->{db};

	my $name_prefix = 'my'.$uid.'_';
	
	# mysql privileges
	my @all_db_privs = qw(
		Select       Insert     Update            Delete     
		Create       Drop       Grant             References 
		Index        Alter      Create_tmp_table  Lock_tables 
		Create_view  Show_view  Create_routine    Alter_routine 
		Execute      Event      Trigger
	);
	my @all_table_privs = (
		'Select', 'Insert', 'Update',      'Delete', 
		'Create', 'Drop',   'Grant',       'References', 
		'Index',  'Alter',  'Create View', 'Show view', 
		'Trigger'
	);
	my @all_column_privs = (
		'Select', 'Insert', 'Update', 'References'
	);

	# build prvilage tree
	# database names based on grants (may not exist on hdd)
	my (%user, %database);
	
	# database grants for users
	$db->{get_db_grants}->execute($name_prefix.'%');
	while(my $col = $db->{get_db_grants}->fetchrow_hashref) {
		my $db_name   = $col->{Db};
		my $user_name = join('@', $col->{User}, $col->{Host});
		my (@set_grants, @unset_grants);
		for (keys %$col) {
			my $grant_name = $_;
			   $grant_name =~ s/_priv$// or next; # skip non-priv columns
			   $grant_name =~ s/_/ /;
			if ($col->{$_} eq 'Y') {
				push @set_grants, $grant_name;
			} else {
				push @unset_grants, $grant_name;
			}
		}
		if (@set_grants > @unset_grants) {
			my $grant_list = @unset_grants ? 'ALL without '.join(q[, ], @unset_grants) : 'ALL with GRANT';
			$user{ $user_name }->{$db_name}->{db_grants} = $grant_list;
		} 
		else {
			$user{ $user_name }->{$db_name}->{db_grants} = join q[, ], @set_grants;
		}
		$database{$db_name}->{$user_name}++;
	}

	# table grants for users
	$db->{get_table_grants}->execute($name_prefix.'%');
	while(my $col = $db->{get_table_grants}->fetchrow_hashref) {
		my $db_name      = $col->{Db};
		my $table_name   = $col->{Table_name};
		my $user_name    = join('@', $col->{User}, $col->{Host});
		my @set_grants   = split(/,/, $col->{Table_priv});
		my @unset_grants = grep { not $_ ~~ @set_grants } @all_table_privs;
		if (@set_grants > @unset_grants) {
			my $grant_list = @unset_grants ? 'ALL without '.join(q[, ], @unset_grants) : 'ALL';
			$user{ $user_name }->{$db_name}->{tables}->{$table_name}->{table_grants} = $grant_list;
		}
		else {
			$user{ $user_name }->{$db_name}->{tables}->{$table_name}->{table_grants} = join q[, ], @set_grants;
		}
		$database{$db_name}->{$user_name}++;
	}

	# columns grants for users
	$db->{get_column_grants}->execute($name_prefix.'%');
	while(my $col =  $db->{get_column_grants}->fetchrow_hashref) {
		my $db_name     = $col->{Db};
		my $table_name  = $col->{Table_name};
		my $column_name = $col->{Column_name};
		my $user_name   = join('@', $col->{User}, $col->{Host});
		my @set_grants  = split(/,/, $col->{Column_priv});
		$user{ $user_name }->{$db_name}->{tables}->{$table_name}->{columns}->{$column_name}->{column_grants} = join q[, ], @set_grants;
		$database{ $db_name }->{$user_name}++;
	}

	#print Dumper(\%user);
	#print Dumper(\%database);
	
	my $detailed_listing = shift @args;
	if ($detailed_listing) {
		if ($detailed_listing eq 'users') {
			# satan mysql list users
			my (@rows, @orphaned);
			
			# get all users
			$db->{get_users}->execute($name_prefix.'%');
			my $real_users = $db->{get_users}->fetchall_arrayref;
			my %real_users = map { join('@', $_->[0], $_->[1]) => 1 } @$real_users;
			print Dumper(\%real_users);
	
			@args > 0 and return "Too many arguments! See help."; 
			foreach my $user (sort keys %user) {
				my ($user_name, $host_name) = split /\@/, $user;
				$host_name = 'any' if $host_name eq '%';
				my $user_databases = join(q[, ], sort keys %{$user{$user}});
				
				# check if orphaned 
				if ($real_users{$user}) {
					push @rows, join("\t", $user_name, $host_name, $user_databases);
					delete $real_users{$user};
				}
			}

			my $listing  = "\033[1;32mUsers\033[0m (".scalar @rows." in total)\n\n";
			   $listing .= "\033[1mUser\tHost\tDatabases\033[0m\n";
			if (@rows) {
				$listing .= join("\n", @rows); 
			} 
			else {
				$listing = "No users.";
			}
		
			# orphaned databases (does not exist on hdd)
			foreach my $user (keys %real_users) {
				my ($user_name, $host_name) = split /\@/, $user;
				$host_name = 'any' if $host_name eq '%';
				push @orphaned, join("\t", $user_name, $host_name, '-');
			}

			if (@orphaned) {
				$listing .= "\n\n\033[1;31mOrphaned entries\033[0m (".scalar @orphaned." in total)\n\n";
			   	$listing .= "\033[1mUsers\033[0m\n";
				$listing .= join("\n", @orphaned);
			}
		
			$self->{listing} = $listing;
		} 
		elsif ($detailed_listing eq 'user') {
			# satan mysql list user <user>
			my $specified_username = shift @args or return "Username NOT specified. Read help.";
			@args > 0 and return "Too many arguments! See help."; 
			return "Not implemented yet. Sorry";
		}
		else {
			# satan mysql list <dbname>
			@args > 0 and return "Too many arguments! See help."; 
			my $db_name = $detailed_listing;
			if ($db_name =~ /^(my${uid}_|)([a-z0-9]+)$/) {
				$db_name = $name_prefix.$2;
			} 
			elsif ($db_name =~ /^my(\d+)_/) {
				return "ID \033[1m$1\033[0m in $db_name is different from your actual uid $uid.";
			}	
			else {
				return "Not good! \033[1m$db_name\033[0m is NOT a proper database name.";
			} 
			my @rows;
			foreach my $user (keys %{$database{$db_name}}) {
				my ($user_name, $host_name) = split /\@/, $user;
				$host_name = 'any' if $host_name eq '%';
				my $db_privs = $user{ $user }->{$db_name}->{db_grants};
				push @rows, join("\t", $user_name, $host_name, $db_privs);
			}
			my $listing = "\033[1;32m$db_name users\033[0m (".scalar @rows." in total)\n";
			if (@rows) {
				$listing .= "\n\033[1mUser name\tHost\tPrivileges\033[0m\n";
				$listing .= join("\n", @rows);
			}
			else {
				$listing = "No users.";
			}
			$self->{listing} = $listing;
		}
	}
	else {
		# satan mysql list
		my (@rows, @orphaned);
		@args > 0 and return "Too many arguments! See help."; 

		# get databases from hdd
		$db->{check_db}->execute($name_prefix.'%');
		my $real_databases = $db->{check_db}->fetchall_arrayref;
		my %real_databases = map { $_->[0] => 1 } @$real_databases;
	
		foreach my $db_name (keys %database) {
			my @users = keys %{$database{$db_name}};
			my @user_names;
			foreach my $user (@users) {
				my($user_name, $host_name) = split /\@/, $user;
				push @user_names, $user_name;
				
			}
			if ($real_databases{$db_name}) {
				push @rows, $db_name."\t".join(q[, ], sort @user_names);	
				delete $real_databases{$db_name};
			} else {
				push @orphaned, $db_name."\t".join(q[, ], sort @user_names);	
			}
		}

		foreach my $db_name (keys %real_databases) {
			push @rows, $db_name."\t".'-';
		}

		my $listing  = "\033[1;32mDatabases\033[0m (".scalar @rows." in total)\n\n";
		   $listing .= "\033[1mDatabase\tUsers\033[0m\n";

		if (@rows) {
			$listing .= join("\n", @rows);
		} 
		else {
			$listing = "No databases.";
		}

		# orphaned databases (does not exist on hdd)
		if (@orphaned) {
			$listing .= "\n\n\033[1;31mOrphaned entries\033[0m (".scalar @orphaned." in total)\n\n";
		   	$listing .= "\033[1mDatabase\tUsers\033[0m\n";
			$listing .= join("\n", @orphaned);
		}

		$self->{listing} = $listing;
	}

	return;
}

=listing
Databases (10 in total)

Name	      Users
my6666_test   my6666_test, my6666_ahes

Users of my6666_test (2 in total)

User name     Database privs     Table name  Table privs      Column name Column privs
my6666_test   ALL without Grant  
			         tabela1     Select, Update   -           -
				 tabela2     Select           -           -
				 tabela1     -                col1        Select	                  

Users (2 in total)

Name          Host    Databases               
my6666_test   all     my6666_test, my1123_aaa

User my6666_test

Database     Table    Column    Privs
my6666_test  -        -         ALL without Grant
                 
=cut

sub help {
	my $self = shift;

	my $USAGE = <<"END_OF_USAGE";
\033[1mSatan::MySQL\033[0m

\033[1;32mSYNTAX\033[0m
  mysql add <dbname> [<pass>]
  mysql add user <user> [<pass>]
  mysql del <dbname>
  mysql del user <user>
  mysql list
  mysql list <dbname>
  mysql list users
  mysql list user <user>
  mysql passwd <user>
END_OF_USAGE

	$self->{listing} = $USAGE;
	return;
}

sub get_data {
        my $self = shift;
        return $self->{listing} || '';
}

