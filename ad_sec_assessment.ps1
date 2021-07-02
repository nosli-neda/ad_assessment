###############################################################################################################################
#
# SCRIPT CRIADO POR: ADENILSON MEZINI
# E-MAIL: ADENILSON@MEZINI.COM.BR
# DATA: 15/06/2020
# MODIFICADO: 19/03/2021
# VERSION: 0.5
# OBJETIVO: AVALIAR A SEGURANÃƒâ€¡A DO ACTIVE DIRECTORY
#
###############################################################################################################################

$DomainName = (Get-ADDomain).Forest
$savepath = (Get-Location).Path
$filename_ASS = "Assessment_" + $DomainName +".html"
$filename_DET = "Detail_" + $DomainName +".html"
$filename_RISK = "Risk_" + $DomainName +".html"

############################################
# CONSTANTS

$CountDomainAdmin = 0
$CountEnterpriseAdmin = 0
$CountBuiltAdmin = 0
#$GroupName = "Domain Admins"

############################################
$path = $savepath +"\" + $filename_ASS
if (Test-Path $savepath\$filename_ASS)
{
    Remove-Item $savepath"\"$filename_ASS
}
if (Test-Path $savepath"\"$filename_DET)
{
    Remove-Item $savepath"\"$filename_DET
}
if (Test-Path $savepath"\"$filename_RISK)
{
    Remove-Item $savepath"\"$filename_RISK
}
New-Item $path -ItemType File


############################################
# FUNCTIONS

############################################
# FUNCTION TEST NESTED GROUPS
function Test-NestedGroups($GroupName)
{
    $count = 0
    $NestedGroup = Get-ADGroupMember -Identity $GroupName | select Name, samAccountNAme, ObjectClass 
    foreach ($member in $NestedGroup)
    {
        if($member.ObjectClass -eq 'group')
        {
            $count = $count + 1
            return $count
        }
    }
}

function Get-PrivUsers($GroupName)
{
    $retorno = $null
    $retorno = @()
    $PrivUsers = Get-ADGroupMember -Identity $GroupName | select Name, samAccountNAme, ObjectClass
    foreach ($member in $PrivUsers)
    {
        $account = $null
        $account = @{} | select Nome, samAccountName, 'Password Never Expires', Enabled
        if ($member.ObjectClass -eq 'user')
        {   
            $admin = Get-ADUser -Identity $member.samAccountNAme -Properties PasswordNeverExpires
            $account.Nome = $admin.Name
            $account.samAccountName = $admin.SamAccountName
            $account.'Password Never Expires' = $admin.PasswordNeverExpires
            $account.Enabled = $admin.Enabled
            $retorno += $account
        }
        elseif ($member.ObjectClass -eq 'group' -and $member.Name -ne "Domain Admins")
        {
            $CountNested1 = Get-ADGroupMember -Identity $member.Name | select Name, samAccountNAme, ObjectClass
            $account.Nome = $member.Name
            $account.samAccountName = "GROUP"
			$account.'Password Never Expires' = " "
            $account.Enabled = " "
            $retorno += $account
            
            foreach ($Member1 in $CountNested1)
            {
                $account = $null
                $account = @{} | select Nome, samAccountName, 'Password Never Expires', Enabled
                if ($member1.ObjectClass -eq 'user')
                {
                    $admin1 = Get-ADUser -Identity $Member1.samAccountNAme -Properties PasswordNeverExpires
                    $account.Nome = $admin1.Name
                    $account.samAccountName = $admin1.SamAccountName
                    $account.'Password Never Expires' = $admin1.PasswordNeverExpires
                    $account.Enabled = $admin1.Enabled
                    $retorno += $account
                }
                elseif ($member1.ObjectClass -eq 'group' -and $member1.Name -ne "Domain Admins")
                {
                    $account.Nome = $member1.Name
					$account.samAccountName = "GROUP"
					$account.'Password Never Expires' = " "
					$account.Enabled = " "
					$retorno += $account
                    $CountNested2 = Get-ADGroupMember -Identity $member1.Name | select Name, samAccountNAme, ObjectClass
                    foreach ($Member2 in $CountNested2)
                    {
                        $account = $null
                        $account = @{} | select Nome, samAccountName, 'Password Never Expires', Enabled
                        if ($member2.ObjectClass -eq 'user')
                        {
                            $admin2 = Get-ADUser -Identity $Member2.samAccountNAme -Properties PasswordNeverExpires
                            $account.Nome = $admin2.Name
                            $account.samAccountName = $admin2.SamAccountName
                            $account.'Password Never Expires' = $admin2.PasswordNeverExpires
                            $account.Enabled = $admin2.Enabled
                            $retorno += $account
                        }
                        elseif ($member2.ObjectClass -eq 'group' -and $member2.Name -ne "Domain Admins")
                        {
                            $account.Nome = $member2.Name
							$account.samAccountName = "GROUP"
							$account.'Password Never Expires' = " "
							$account.Enabled = " "
							$retorno += $account
                            
                            $CountNested3 = Get-ADGroupMember -Identity $member2.Name | select Name, samAccountNAme, ObjectClass
                            foreach ($Member3 in $CountNested3)
                            {
                                $account = $null
                                $account = @{} | select Nome, samAccountName, 'Password Never Expires', Enabled
                                if ($member3.ObjectClass -eq 'user')
                                {
                                    $admin3 = Get-ADUser -Identity $Member3.samAccountNAme -Properties PasswordNeverExpires
                                    $account.Nome = $admin3.Name
                                    $account.samAccountName = $admin3.SamAccountName
                                    $account.'Password Never Expires' = $admin3.PasswordNeverExpires
                                    $account.Enabled = $admin3.Enabled
                                    $retorno += $account
                                }
                                elseif ($member3.ObjectClass -eq 'group' -and $member3.Name -ne "Domain Admins")
                                {
                                    $account.Nome = $member3.Name
									$account.samAccountName = "GROUP"
									$account.'Password Never Expires' = " "
									$account.Enabled = " "
									$retorno += $account
									
                                    $CountNested4 = Get-ADGroupMember -Identity $member3.Name | select Name, samAccountNAme, ObjectClass
                                    foreach ($Member4 in $CountNested4)
                                    {
                                        $account = $null
                                        $account = @{} | select Nome, samAccountName, 'Password Never Expires', Enabled
                                        if ($member4.ObjectClass -eq 'user')
                                        {
                                            $admin4 = Get-ADUser -Identity $Member4.samAccountNAme -Properties PasswordNeverExpires
                                            $account.Nome = $admin4.Name
                                            $account.samAccountName = $admin4.SamAccountName
                                            $account.'Password Never Expires' = $admin4.PasswordNeverExpires
                                            $account.Enabled = $admin4.Enabled
                                            $retorno += $account
                                        }
                                        elseif ($member4.ObjectClass -eq 'group' -and $member4.Name -ne "Domain Admins")
                                        {
                                            $account.Nome = $member4.Name
											$account.samAccountName = "GROUP"
											$account.'Password Never Expires' = " "
											$account.Enabled = " "
											$retorno += $account
											
                                            $CountNested5 = Get-ADGroupMember -Identity $member4.Name | select Name, samAccountNAme, ObjectClass
                                            foreach ($Member5 in $CountNested5)
                                            {
                                                $account = $null
                                                $account = @{} | select Nome, samAccountName, 'Password Never Expires', Enabled
                                                if ($member5.ObjectClass -eq 'user')
                                                {
                                                    $admin5 = Get-ADUser -Identity $Member5.samAccountNAme -Properties PasswordNeverExpires
                                                    $account.Nome = $admin5.Name
                                                    $account.samAccountName = $admin5.SamAccountName
                                                    $account.'Password Never Expires' = $admin5.PasswordNeverExpires
                                                    $account.Enabled = $admin5.Enabled
                                                    $retorno += $account
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return $retorno
}    
    
###########################################################
# Function Count Privileged Users

function Get-CountPrivUsers($GroupName)
{
   	[hashtable]$return = @{}
    $count = 0
    $passneverexpires = 0
    $CountPrivUsers = Get-ADGroupMember -Identity $GroupName | select Name, samAccountNAme, ObjectClass
    foreach ($member in $CountPrivUsers)
    {
        if ($member.ObjectClass -eq 'user')
        {
            $count = $count + 1
            $admin = Get-ADUser -Identity $member.SamAccountName -Properties PasswordNeverExpires
            if($admin.PasswordNeverExpires) { $passneverexpires ++ }
        }
        elseif ($member.ObjectClass -eq 'group' -and $member.Name -ne "Domain Admins")
        {
            $CountNested1 = Get-ADGroupMember -Identity $member.Name | select Name, samAccountNAme, ObjectClass
            foreach ($nested1 in $CountNested1)
            {
                if ($nested1.ObjectClass -eq 'user')
                {
                    $count = $count +1 
                    $admin = Get-ADUser -Identity $nested1.SamAccountName -Properties PasswordNeverExpires
            if($admin.PasswordNeverExpires) { $passneverexpires ++ }
                }
                elseif ($nested1.ObjectClass -eq 'group'-and $member.Name -ne "Domain Admins")
                {
                    $CountNested2 = Get-ADGroupMember -Identity $nested1.Name | select Name, samAccountNAme, ObjectClass
                    foreach ($nested2 in $CountNested2)
                    {
                        if ($nested2.ObjectClass -eq 'user')
                        {
                            $count = $count +1 
                            $admin = Get-ADUser -Identity $nested2.SamAccountName -Properties PasswordNeverExpires  
                        }
                        elseif ($nested2.ObjectClass -eq 'group'-and $member.Name -ne "Domain Admins")
                        {
                            $CountNested3 = Get-ADGroupMember -Identity $nested2.Name | select Name, samAccountNAme, ObjectClass
                            foreach ($nested3 in $CountNested3)
                            {
                                if ($nested3.ObjectClass -eq 'user')
                                {
                                    $count = $count +1  
                                    $admin = Get-ADUser -Identity $nested3.SamAccountName -Properties PasswordNeverExpires
                                }
                                elseif ($nested3.ObjectClass -eq 'group'-and $member.Name -ne "Domain Admins")
                                {
                                    $CountNested4 = Get-ADGroupMember -Identity $nested3.Name | select Name, samAccountNAme, ObjectClass
                                    foreach ($nested4 in $CountNested4)
                                    {
                                        if ($nested4.ObjectClass -eq 'user')
                                        {
                                            $count = $count +1  
                                            $admin = Get-ADUser -Identity $nested4.SamAccountName -Properties PasswordNeverExpires
                                        }
                                        elseif ($nested4.ObjectClass -eq 'group'-and $member.Name -ne "Domain Admins")
                                        {
                                            $CountNested5 = Get-ADGroupMember -Identity $nested4.Name | select Name, samAccountNAme, ObjectClass
                                            foreach ($nested5 in $CountNested5)
                                            {
                                                if ($nested5.ObjectClass -eq 'user')
                                                {
                                                    $count = $count +1  
                                                    $admin = Get-ADUser -Identity $nested5.SamAccountName -Properties PasswordNeverExpires
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
	$return.countAdmin = $count
	$return.passneverexpires = $passneverexpires
    RETURN $RETURN
}

##########################################################
# Function Count User Never EXPIRES

function Get-UserNeverExpires ()
{
    $users = Get-ADUser -Filter * -Properties PasswordNeverExpires
    $UserPassNeverExpires = 0
    foreach ($member in $users)
    {
        if($member.ObjectClass -eq 'user')
        {
            $user = Get-ADUser $member.samAccountNAme -Properties *
            if($user.PasswordNeverExpires)
            {
    			$UserPassNeverExpires ++
            }
        }
    }
    return $UserPassNeverExpires
}

##########################################################
# SUMÃRIO Issues
##########################################################


##############################################################
# GET USRS WITH SID HISTORY
$userssid = Get-ADUser -Filter * -Properties sidhistory
$totaluserssid = 0
$UsersSidHist = $null
$UsersSidHist= @()
foreach ($user in $userssid)
{
    $account = $null
    $account = @{} | select Nome, samAccountName, SIDHistory, Enabled
    if($user.sidHistory)
    {
        $account.Nome = $user.Name 
        $account.samAccountName = $user.SamAccountName
        $account.SIDHistory = (New-Object System.Security.Principal.SecurityIdentifier($user.SIDHistory)).Translate([System.Security.Principal.NTAccount]).value
        $account.Enabled = $user.Enabled
        $UserSidHist = $account
        $totaluserssid += 1 
    }
}


#################
# PASSWORD STORED IN REVERSIBLE ENCRYPTION

$Users = Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
$CountReversibleEncrypt = 0
$UsersReverseEncrypt = $null
$UsersReverseEncrypt = @()
foreach ($User in $Users)
{
    $account = $null
    $account = @{} | select Nome, samAccountName, ReversePassword, Enabled

        $CountReversibleEncrypt ++ 
        $account.Nome = $user.Name
        $account.samAccountName = $user.samAccountNAme
	    $account.ReversePassword = "True"
        $account.Enabled = $user.ENABLED
        $UsersReverseEncrypt += $account

}


#################
# ADMINCOUNT > 0

$Users = get-aduser -Filter {admincount -gt 0} -Properties adminCount -ResultSetSize $null 
$CountAdminCount = 0
$UsersAdminCount = $null
$UsersAdminCount = @()
foreach ($User in $Users)
{
	$account = $null
    $account = @{} | select Nome, samAccountName, 'AdminCount', Enabled
    $account.Nome = $user.Name
    $account.samAccountName = $user.samAccountNAme
	$account.adminCount = $user.adminCount
    $account.Enabled = $user.ENABLED
    $UsersAdminCount += $account
    $CountAdminCount ++ 
}

#################
# KERBEROASTING

$ldapFilter = "(&(objectclass=user)(objectcategory=user)(servicePrincipalName=*))"
$domain = New-Object System.DirectoryServices.DirectoryEntry
$search = New-Object System.DirectoryServices.DirectorySearcher
$search.SearchRoot = $domain
$search.PageSize = 1000
$search.Filter = $ldapFilter
$search.SearchScope = "Subtree"
$results = $search.FindAll()
$CountKerberoAsting = 0
$AccountSPN = $null
$AccountSPN = @()
foreach ($result in $results)
{

    $userEntry = $result.GetDirectoryEntry()
    foreach ($SPN in $userEntry.servicePrincipalName)
    {
        $account = $null
        $account = @{} | select "SPN"
        $account.SPN = $SPN
        $AccountSPN += $Account.SPN
        $CountKerberoAsting ++
    }
}

#################
# ASREPROASTING

$asreproasting = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth
$users = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth
$CountAsRepRoasting = 0
$UsersAsRepRoasting = $null
$UsersAsRepRoasting = @()
foreach ($user in $users)
{
	$account = $null
    $account = @{} | select Nome, samAccountName, 'DoesNotRequirePreAuth', Enabled
    if ($user.DoesNotRequirePreAuth)
    {
		$account.Nome = $user.Name
        $account.samAccountName = $user.samAccountNAme
		$account.DoesNotRequirePreAuth = $user.DoesNotRequirePreAuth
        $account.Enabled = $user.ENABLED
        $UsersAsRepRoasting += $account
        $CountAsRepRoasting ++ 
    }
}

################################
# List userAccountControl - Password Not Required - Password Never EXPIRES
$users = Get-ADUser -Filter * -Properties userAccountControl
$CountPassNotRequired = 0
$CountPassDontExpire = 0
$UsersPassNotReq = $null
$UsersPassNotReq = @()
foreach ($user in $users)
{
	$account = $null
    $account = @{} | select Nome, samAccountName, AccountControl, Enabled

    if ($user.useraccountControl -eq 544 -or $user.useraccountControl -eq 546 )#-or $user.useraccountControl -eq 66080 -or $user.useraccountControl -eq 66082)
    {
		$account.Nome = $user.Name
        $account.samAccountName = $user.samAccountNAme
		$account.Accountcontrol= $user.userAccountControl
        $account.Enabled = $user.ENABLED
		$usersPassNotReq += $account
        $CountPassNotRequired ++
    }
    #elseif ($user.useraccountControl -eq 66048 -or $user.useraccountControl -eq 66050 -or $user.useraccountControl -eq 66080 -or $user.useraccountControl -eq 66082)
    #{
    #    $CountPassNotRequired = 0
	#	$account.Nome = $user.Name
    #    $account.samAccountName = $user.samAccountNAme
	#	$account.Accountcontrol= $user.userAccountControl
    #    $account.Enabled = $user.ENABLED
	#	$usersPassNotReq += $account
    #}
}



##############################################################################################################
# GET PRIVILEGED USERS
$CountDomainAdmin = (Get-CountPrivUsers("Domain Admins")).countAdmin
$CountEnterpriseAdmin = (Get-CountPrivUsers("Enterprise Admins")).countAdmin
$CountBuiltAdmin = (Get-CountPrivUsers("Administrators")).countAdmin
$CountSchemaAdmin = (Get-CountPrivUsers("Schema Admins")).countAdmin

$NeverDomainAdmin = (Get-CountPrivUsers("Domain Admins")).passneverexpires
$NeverEnterpriseAdmin = (Get-CountPrivUsers("Enterprise Admins")).passneverexpires
$NeverBuiltAdmin = (Get-CountPrivUsers("Administrators")).passneverexpires
$NeverSchemaAdmin = (Get-CountPrivUsers("Schema Admins")).passneverexpires


#####################################
# GET TOTAL USERS OF DOMAIN
$numberofusers = (Get-ADUser -Filter *).count
$CountUserNeverExpires = Get-UserNeverExpires
$numberprivilegedusers = $CountDomainAdmin + $CountEnterpriseAdmin + $CountBuiltAdmin + $CountSchemaAdmin
$CountPrivilegedNeverExpires = $NeverDomainAdmin + $NeverEnterpriseAdmin + $NeverBuiltAdmin + $NeverSchemaAdmin




############################################
# CREATE CHARTS
############################################
Set-Content $path '<html>'
Add-Content $path '	<HEAD>'
Add-Content $path '    <style>'
Add-Content $path '        .cssHeaderRow {'
Add-Content $path '            background-color: #8EA1A4;'
Add-Content $path '        }'
Add-Content $path '        .cssTableRow {'
Add-Content $path '            background-color: #F0F1F2;'
Add-Content $path '        }'
Add-Content $path '        .cssOddTableRow {'
Add-Content $path '            background-color: #F0F1F2;'
Add-Content $path '        }'
Add-Content $path '        .cssSelectedTableRow {'
Add-Content $path '            font-size: 14px;'
Add-Content $path '            font-weight:bold;'
Add-Content $path '        }'
Add-Content $path '        .cssHoverTableRow {'
Add-Content $path '            background: #ccc;'
Add-Content $path '        }'
Add-Content $path '        .cssHeaderCell {'
Add-Content $path '            color: #FFFFFF;'
Add-Content $path '            font-size: 14px;'
Add-Content $path '            border: solid 1px #FFFFFF;'
Add-Content $path '        }'
Add-Content $path '        .cssTableCell {'
Add-Content $path '            font-size: 12px;'
Add-Content $path '            border: solid 1px #FFFFFF;'
Add-Content $path '            text-align: center;'
Add-Content $path '        }'
Add-Content $path '        .cssRowNumberCell {'
Add-Content $path '            text-align: center;'
Add-Content $path '        }'
Add-Content $path '    </style>'


Add-Content $path '	    <TITLE> DOMAIN ASSESSMENT </TITLE>'

############################################
# CREATE PRIVILEGED USERS BAR CHART
Add-Content $path '		<script src="https://www.gstatic.com/charts/loader.js"></script>'
Add-Content $path '		<script>'
Add-Content $path "			google.charts.load('current', {packages: ['corechart']});"
Add-Content $path '			google.charts.setOnLoadCallback(drawChart);'
Add-Content $path '			function drawChart()'
Add-Content $path '			{'
Add-Content $path "				const container = document.querySelector('#chart')"
Add-Content $path '				const data = new google.visualization.arrayToDataTable(['
Add-Content $path "					[ 'Groups', 'Members'],"
Add-Content $path "					[ 'Enterprise Admins', $CountEnterpriseAdmin ],"
Add-Content $path "					[ 'Schema Admins', $CountSchemaAdmin ],"
Add-Content $path "					[ 'Domain Admins', $CountDomainAdmin ],"
Add-Content $path "					[ 'Built-in Admins', $CountBuiltAdmin ]"
Add-Content $path "				])"
Add-Content $path "				const options = {"
Add-Content $path "					title: 'Privileged Users',"
Add-Content $path "					height: 300,"
Add-Content $path "					weight: 720,"
Add-Content $path "					legend: { position: 'none' },"
Add-Content $path "				}"
Add-Content $path "				const chart = new google.visualization.ColumnChart(container)"
Add-Content $path "				chart.draw(data,options)"
Add-Content $path "			}"

#########################################
# CREATE PIE CHART - PRIV vs COMMON USERS
Add-Content $path "			google.charts.setOnLoadCallback(drawPie);"
Add-Content $path "			function drawPie()"
Add-Content $path "			{"
Add-Content $path "				const data = google.visualization.arrayToDataTable(["
Add-Content $path "					['Type Users', 'Users'],"
Add-Content $path "					['Common Users', $numberofusers],"
Add-Content $path "					['Privileged Users', $numberprivilegedusers]"
Add-Content $path "				]);"
Add-Content $path "				const options = {"
Add-Content $path "					title: 'Privileged Users vs Common Users'"
Add-Content $path "				};"
Add-Content $path "				const chart = new google.visualization.PieChart(document.getElementById('piechartpriv'));"
Add-Content $path "				chart.draw(data, options);"
Add-Content $path "			}"

########################################
# CREATE PIE CHART - PASS NEVER EXPIRES
Add-Content $path "			google.charts.setOnLoadCallback(drawPieExpira);"
Add-Content $path "			function drawPieExpira()"
Add-Content $path "			{"
Add-Content $path "				const data = google.visualization.arrayToDataTable(["
Add-Content $path "					['PASS Never Expires', 'Users'],"
Add-Content $path "					['Password Expires', $numberofusers],"
Add-Content $path "					['Password Never Expires', $CountUserNeverExpires]"
Add-Content $path "				]);"
Add-Content $path "				const options = {"
Add-Content $path "					title: 'Total Users - Password Never Expires'"
Add-Content $path "				};"
Add-Content $path "				const chart = new google.visualization.PieChart(document.getElementById('piechartexpira'));"
Add-Content $path "				chart.draw(data, options);"
Add-Content $path "			}"
Add-Content $path "			google.charts.setOnLoadCallback(drawPiePrivExpira);"

#########################################
# CREATE PIE CHART - PRIV USER PASS NEVER EXPIRES
Add-Content $path "			function drawPiePrivExpira()"
Add-Content $path "			{"
Add-Content $path "				const data = google.visualization.arrayToDataTable(["
Add-Content $path "					['PWD Never Expires', 'Users'],"
Add-Content $path "					['Password Expires', $numberprivilegedusers - $CountPrivilegedNeverExpires ],"
Add-Content $path "					['Password Never Expires', $CountPrivilegedNeverExpires]"
Add-Content $path "				]);"
Add-Content $path "				const options = {"
Add-Content $path "					title: 'Priv Users - Password Never Expires'"
Add-Content $path "				};"
Add-Content $path "				const chart = new google.visualization.PieChart(document.getElementById('piechartprivexpira'));"
Add-Content $path "				chart.draw(data, options);"
Add-Content $path "			}"

#########################################
# CREATE BAR CHART - ISSUES
			
Add-Content $path "			google.charts.load('current', {'packages':['bar']});"
Add-Content $path "			google.charts.setOnLoadCallback(barChartAccounts);"
Add-Content $path "			function barChartAccounts()"
Add-Content $path "			{"
Add-Content $path "				var data = new google.visualization.arrayToDataTable(["
Add-Content $path "					['Issues', 'Accounts'],"
Add-Content $path "					['AdminCount', $CountAdminCount],"
Add-Content $path "					['Password Not Required', $CountPassNotRequired],"
#Add-Content $path "					['Password Never Expires', $CountPassDontExpire],"
Add-Content $path "					['KerberoASTING', $CountKerberoAsting],"
Add-Content $path "					['Password Using Reversing Encryption', $CountReversibleEncrypt],"
Add-Content $path "					['Does Not Require PreAuth Kerberus', $CountAsRepRoasting ],"
Add-Content $path "					['Users with SID History', $totaluserssid ],"

Add-Content $path "				]);"
Add-Content $path "				var options = {"
Add-Content $path '					width: "100%",'
Add-Content $path "					chart: {"
Add-Content $path "						title: 'Issues Found in Accounts'"
Add-Content $path "					},"
Add-Content $path "					legend: {position: 'none'},"
Add-Content $path "					bars: 'horizontal', // Required for Material Bar Charts."
Add-Content $path "				};"
Add-Content $path "				var chart = new google.charts.Bar(document.getElementById('chartBarAccounts'));"
Add-Content $path "				chart.draw(data, options);"
Add-Content $path "			};"



#################################################################################################
# CREATE TABLE CHART - DOMAIN TRUST

Add-Content $path "				  google.charts.load('current', {'packages':['table']});"
Add-Content $path "			      google.charts.setOnLoadCallback(drawTableTrust);"

Add-Content $path "			      function drawTableTrust()"
Add-Content $path "			      {"
Add-Content $path "			        var data = new google.visualization.DataTable();"
Add-Content $path "			        data.addColumn('string', 'Source' );"
Add-Content $path "			        data.addColumn('string', 'Target');"
Add-Content $path "			        data.addColumn('string', 'Direction');"
Add-Content $path "					data.addColumn('boolean', 'Transitive');"
Add-Content $path "					data.addColumn('boolean', 'TGT Delegation');"
Add-Content $path "					data.addColumn('boolean', 'Users RC4');"

                                            
                                            ######################################
                                            # LIST ALL TRUST
                                            $AdTrust = Get-ADTrust -Filter * 
                                            $count = $AdTrust.count
											if (!$count)
											{
												$count = 1
											}
                                            $i=0
Add-Content $path "                         data.addRows(["
                                            foreach($Trust in $AdTrust)
                                            {
                                                $i++
												$DomTarget = $trust.Target
												$DomDir = $Trust.Direction 
                                                if($trust.UsesRC4Encryption){$DomRC4 = 'true'}else{$DomRC4 = 'false'}
												if($trust.TGTDelegation){$DomTGT = 'true'}else{$DomTGT = 'false'}
                                                if($trust.ForestTransitive){$DomTrans = 'true'}else{$DomTrans = 'false'}
                                                if($i -lt $count)
                                                {
                                                    Add-Content $path "['$domainName', '$DomTarget', '$DomDir', $DomTrans, $DomTGT, $DomRC4 ]," 
                                                }
                                                else
                                                {
                                                    Add-Content $path "['$domainName', '$DomTarget', '$DomDir', $DomTrans, $DomTGT, $DomRC4 ]" 
                                                }
                                                
                                            }
Add-Content $path "                 ]);"
Add-Content $path "                 var cssClassNames = {"
Add-Content $path "                     'headerRow': 'cssHeaderRow',"
Add-Content $path "                     'tableRow': 'cssTableRow',"
Add-Content $path "                     'oddTableRow': 'cssOddTableRow',"
Add-Content $path "                     'selectedTableRow': 'cssSelectedTableRow',"
Add-Content $path "                     'hoverTableRow': 'cssHoverTableRow',"
Add-Content $path "                     'headerCell': 'cssHeaderCell',"
Add-Content $path "                     'tableCell': 'cssTableCell',"
Add-Content $path "                     'rowNumberCell': 'cssRowNumberCell'"
Add-Content $path "                 };"
Add-Content $path "                                 "
Add-Content $path "                 var options = {"
Add-Content $path "                     showRowNumber: true,"
Add-Content $path "                     width: '100%',"
Add-Content $path "                     cssClassNames: cssClassNames"
Add-Content $path "                 };"
Add-Content $path "			        var table = new google.visualization.Table(document.getElementById('tableTrust'));"
Add-Content $path "			        table.draw(data, options);"
Add-Content $path "			      }"
    



#################################################################################################
# CREATE TABLE CHART - DOMAIN TRUST

Add-Content $path "			google.charts.load('current', {'packages':['table']});"
Add-Content $path "			      google.charts.setOnLoadCallback(drawTableDC);"

Add-Content $path "			      function drawTableDC()"
Add-Content $path "			      {"
Add-Content $path "			        var data = new google.visualization.DataTable();"
Add-Content $path "			        data.addColumn('string', 'Hostname');"
Add-Content $path "			        data.addColumn('string', 'IPv4');"
Add-Content $path "			        data.addColumn('string', 'Operating System');"
Add-Content $path "					data.addColumn('boolean', 'RODC');"
Add-Content $path "					data.addColumn('string', 'Site');"
Add-Content $path "					data.addColumn('string', 'Domain');"
Add-Content $path "					data.addColumn('string', 'Forest');"
Add-Content $path "					data.addColumn('boolean', 'Enabled');"

                                            
                                            ######################################
                                            # LIST ALL DC
                                            $DomainControllers = Get-ADDomainController -filter * 
                                            $count = $DomainControllers.count
											if (!$count)
											{
												$count = 1
											}
											$i=0
Add-Content $path "                         data.addRows(["
                                            foreach($DC in $DomainControllers)
                                            {
                                                $i++
                                                $dcName = $dc.Name
                                                $dcIPv4 = $dc.IPv4Address
                                                $dcOS= $dc.OperatingSystem
                                                $dcRODC= $dc.IsReadOnly
                                                if($dc.IsReadOnly){$dcRODC = 'true'}else{$dcRODC = 'false'}
                                                $dcSite= $dc.Site
                                                $dcDomain = $dc.Domain
                                                $dcForest= $dc.Forest
                                                if($dc.Enabled){$dcEnabled = 'true'}else{$dcEnabled = 'false'}
                                                if($i -lt $count)
                                                {
                                                    Add-Content $path "['$dcName', '$dcIPv4', '$dcOS', $dcRODC, '$dcSite', '$dcDomain', '$dcForest', $dcEnabled ]," 
                                                }
                                                else
                                                {
                                                    Add-Content $path "['$dcName', '$dcIPv4', '$dcOS', $dcRODC, '$dcSite', '$dcDomain', '$dcForest', $dcEnabled ]" 
                                                }
                                                
                                            }
Add-Content $path "                 ]);"
Add-Content $path "                 var cssClassNames = {"
Add-Content $path "                     'headerRow': 'cssHeaderRow',"
Add-Content $path "                     'tableRow': 'cssTableRow',"
Add-Content $path "                     'oddTableRow': 'cssOddTableRow',"
Add-Content $path "                     'selectedTableRow': 'cssSelectedTableRow',"
Add-Content $path "                     'hoverTableRow': 'cssHoverTableRow',"
Add-Content $path "                     'headerCell': 'cssHeaderCell',"
Add-Content $path "                     'tableCell': 'cssTableCell',"
Add-Content $path "                     'rowNumberCell': 'cssRowNumberCell'"
Add-Content $path "                 };"
Add-Content $path "                                 "
Add-Content $path "                 var options = {"
Add-Content $path "                     showRowNumber: true,"
Add-Content $path "                     width: '100%',"
Add-Content $path "                     cssClassNames: cssClassNames"
Add-Content $path "                 };"
Add-Content $path "			        var table = new google.visualization.Table(document.getElementById('tableDC'));"
Add-Content $path "			        table.draw(data, options);"
 
#{showRowNumber: true, width: '100%'});"

Add-Content $path "			      }"
    

Add-Content $path "		</script>"
Add-Content $path "	</HEAD>"

##########################################
# BODY
# CREATE TABLE TITLE
Add-Content $path "	<BODY>"
Add-Content $path "		<table border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "	    			<TD align=LEFT bgcolor = '#6F8487' style='color:white'>"
Add-Content $path "	    				<h2>ACTIVE DIRECTORY ASSESSMENT REPORT: <span style='color: #2EBED8'>$DomainName</span></H2>"
Add-Content $path '	    			</TD>'
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"
Add-Content $path "		<TABLE border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TD  align=center bgcolor = '#8EA1A4' style='color:white' WIDTH = '20%'>"
Add-Content $path "					<A HREF=$filename_ASS STYLE='COLOR:WHITE bgcolor=#8EA1A4'><H2>GRÃFICOS</H2></A>"
Add-Content $path "				</TD>"
Add-Content $path "				<TD  align=center bgcolor = '#95A2A4' style='color:white' WIDTH = '20%'>"
Add-Content $path "					<A HREF=$filename_DET STYLE='COLOR:WHITE' ><H2>DETALHES</H2></A>"
Add-Content $path "				</TD>"
Add-Content $path "				<TD  align=center bgcolor = '#95A2A4' style='color:white' WIDTH = '20%'>"
Add-Content $path "					<A HREF=$filename_RISK STYLE='COLOR:WHITE'><H2>RISCOS</H2></A>"
Add-Content $path "				</TD>" 
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"
#########################################
# TABLE CHART PRIVILEGED USERS
Add-Content $path "		<TABLE border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TD  align=center bgcolor = 'white' style='color:white' WIDTH = '20%'>"
Add-Content $path '					<div id="chart" style="width: 77%"></div>'
Add-Content $path "				</TD>"
Add-Content $path "			</TR>"
Add-Content $path "		</table>"

########################################
# TABLE PIE CHART
Add-Content $path "		<HR>"
Add-Content $path "		<TABLE border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TD>"
Add-Content $path '					<div id="piechartpriv" style="width: 440px; height: 300px;"></div>'
Add-Content $path "				</TD>"
Add-Content $path "				<TD>"
Add-Content $path '					<div id="piechartprivexpira" style="width: 440px; height: 300px;"></div>'
Add-Content $path "				</TD>"
Add-Content $path "				<TD>"
Add-Content $path '					<div id="piechartexpira" style="width: 440px; height: 300px;"></div>'
Add-Content $path "				</TD>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"
Add-Content $path "		<HR>"

########################################
# TABLE BAR CHART
Add-Content $path "		<TABLE border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TD>"
Add-Content $path '					<div id="chartBarAccounts" style="width: 100%; height: 300px;"></div>'
Add-Content $path "				</TD>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"

########################################
# TABLE DCs
Add-Content $path "		<TABLE border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<Th  align=left bgcolor = '#6F8487' style='color:white'>"
Add-Content $path '					LIST OF DOMAIN CONTROLLERS'
Add-Content $path "				</TH>"
Add-Content $path "			</TR>"


Add-Content $path "			<TR>"
Add-Content $path "				<TD>"
Add-Content $path '					<div id="tableDC" style="align: left" ></div>'
Add-Content $path "				</TD>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"



########################################
# TABLE TRUST

Add-Content $path "		<TABLE border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<Th  align=left  bgcolor = '#6F8487' style='color:white'>"
Add-Content $path '					LIST OF TRUSTS'
Add-Content $path "				</TH>"
Add-Content $path "			</TR>"
Add-Content $path "			<TR>"
Add-Content $path "				<TD>"
Add-Content $path '					<div id="tableTrust" style="align: right ; width: 100%"></div>'
Add-Content $path "				</TD>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"
Add-Content $path "		<HR>"


Add-Content $path "	</BODY>"
Add-Content $path "</HTML>"






####################################################################################################
# CREATE HTML DETAILS

$path = $savepath + "\" + $filename_DET

############################################
# CREATE CHARTS
############################################
Set-Content $path '<html>'
Add-Content $path '	<HEAD>'
Add-Content $path '	    <TITLE> DOMAIN ASSESSMENT </TITLE>'
##########################################
# BODY
# CREATE TABLE TITLE
Add-Content $path "	<BODY>"
Add-Content $path "		<table border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "	    			<TD align=LEFT bgcolor = '#6F8487' style='color:white'>"
Add-Content $path "	    				<h2>ACTIVE DIRECTORY ASSESSMENT REPORT: <span style='color: #2EBED8'>$DomainName</span></H2>"
Add-Content $path '	    			</TD>'
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"
Add-Content $path "		<TABLE border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TD  align=center bgcolor = '#95A2A4' style='color:white' WIDTH = '20%'>"
Add-Content $path "					<A HREF=$filename_ASS STYLE='COLOR:WHITE'><H2>GRÁFICOS</H2></A>"
Add-Content $path "				</TD>"
Add-Content $path "				<TD  align=center bgcolor = '#8EA1A4' style='color:white' WIDTH = '20%'>"
Add-Content $path "					<A HREF=$filename_DET STYLE='COLOR:WHITE bgcolor=#8EA1A4'><H2>DETALHES</H2></A>"
Add-Content $path "				</TD>"
Add-Content $path "				<TD  align=center bgcolor = '#95A2A4' style='color:white' WIDTH = '20%'>"
Add-Content $path "					<A HREF=$filename_RISK STYLE='COLOR:WHITE'><H2>RISCOS</H2></A>"
Add-Content $path "				</TD>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"

#########################################
# TABLE PRIVILEGED USERS


Add-Content $path "		<table border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TH align=LEFT bgcolor = '#6F8487' style='color:white'>"
Add-Content $path "					 PRIVILEGED ACCOUNTS"
Add-Content $path "				</TH>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"

Add-Content $path "	<TABLE border = 0 style='width:100%'>"
Add-Content $path "	  <TR>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      Group Name"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '30%'>"
Add-Content $path "	      NAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '15%'>"
Add-Content $path "	      SAMACCOUNTNAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      PASSWORD NEVER EXPIRES"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:white' WIDTH = '15%'>"
Add-Content $path "	      ENABLED"
Add-Content $path "	    </TH>"
Add-Content $path "	  </TR>"

$PrivGroupName = "Domain Admins", "Schema Admins", "Enterprise Admins" ,"Administrators"
foreach ($group in $PrivGroupName)
{
    $PrivUsers = Get-PrivUsers("$group")
    foreach ($admin in $PrivUsers)
    {
        $AdminNome = $admin.Nome
        $AdminConta = $admin.samAccountName
        $AdminExpira = $admin.'Password Never Expires'
        $AdminEnabled = $admin.Enabled
        Add-Content $path "  <tR>"
        Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '20%'>"
        Add-Content $path "      $group"
        Add-Content $path "    </td>"
        Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '30%'>"
        Add-Content $path "      $AdminNome"
        Add-Content $path "    </td>"
        Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
        Add-Content $path "      $adminConta"
        Add-Content $path "    </td>"
        Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '20%'>"
        Add-Content $path "      $AdminExpira"
        Add-Content $path "    </td>"
        Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
        Add-Content $path "      $AdminEnabled"
        Add-Content $path "    </td>"
        Add-Content $path "  </tr>"
    }
}

Add-Content $path "				</TD>"
Add-Content $path "			</TR>"
Add-Content $path "		</table>"

################################################################
# ADMIN COUNT
Add-Content $path "		<table border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TH align=LEFT bgcolor = '#6F8487' style='color:white'>"
Add-Content $path "					 ADMINCOUNT"
Add-Content $path "				</TH>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"

Add-Content $path "	<TABLE border = 0 style='width:100%'>"
Add-Content $path "	  <TR>"

Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '40%'>"
Add-Content $path "	      NAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      SAMACCOUNTNAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      ADMINCOUNT"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      ENABLED"
Add-Content $path "	    </TH>"
Add-Content $path "	  </TR>"


foreach ($user in $UsersAdminCount)
{
    $userNome = $user.Nome
    $userConta = $user.samAccountName
    $userAC = $user.admincount
    $userEnabled = $user.Enabled
    Add-Content $path "  <tR>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '30%'>"
    Add-Content $path "      $userNome"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
    Add-Content $path "      $userConta"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '20%'>"
    Add-Content $path "      $userAC"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
    Add-Content $path "      $userEnabled"
    Add-Content $path "    </td>"
    Add-Content $path "  </tr>"
}
Add-Content $path "    </TR>"
Add-Content $path "  </table>"

################################################################
# PASSWORD NOT REQUIRED
Add-Content $path "		<table border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TH align=LEFT bgcolor = '#6F8487' style='color:white'>"
Add-Content $path "					 PASSWORD NOT REQUIRED - userAccountControl Attribute"
Add-Content $path "				</TH>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"

Add-Content $path "	<TABLE border = 0 style='width:100%'>"
Add-Content $path "	  <TR>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '40%'>"
Add-Content $path "	      NAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      SAMACCOUNTNAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      userAccountControl"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:black' WIDTH = '20%'>"
Add-Content $path "	      ENABLED"
Add-Content $path "	    </TH>"
Add-Content $path "	  </TR>"

foreach ($user in $usersPassNotReq)
{
    $userNome = $user.Nome
    $userConta = $user.samAccountName
    $userAC = $user.AccountControl
    $userEnabled = $user.Enabled
    Add-Content $path "  <tR>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '30%'>"
    Add-Content $path "      $userNome"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
    Add-Content $path "      $userConta"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '20%'>"
    Add-Content $path "      $userAC"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
    Add-Content $path "      $userEnabled"
    Add-Content $path "    </td>"
    Add-Content $path "  </tr>"
}
Add-Content $path "    </TR>"
Add-Content $path "  </table>"



################################################################
# KERBEROASTING
Add-Content $path "		<table border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TH align=LEFT bgcolor = '#6F8487' style='color:white'>"
Add-Content $path "					 KERBEROASTING - SPN - SERVICE ACCOUNTS"
Add-Content $path "				</TH>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"

Add-Content $path "	<TABLE border = 0 style='width:100%'>"
Add-Content $path "	  <TR>"
Add-Content $path "	    <TH align=LEFT bgcolor = 'white' style='color:BLACK' WIDTH = '5%'>"
Add-Content $path "	      "
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=LEFT bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '95%'>"
Add-Content $path "	      SPN"
Add-Content $path "	    </TH>"
Add-Content $path "	  </TR>"

foreach ($user in $AccountSPN)
{
    $userSPN = $user
    Add-Content $path "  <tR>"
    Add-Content $path "    <td align=left bgcolor = 'WHITE' style='color:BLACK' WIDTH = '5%'>"
    Add-Content $path "      "
    Add-Content $path "    </td>"

    Add-Content $path "    <td align=left bgcolor = 'WHITE' style='color:BLACK' WIDTH = '95%'>"
    Add-Content $path "      $userSPN"
    Add-Content $path "    </td>"
    Add-Content $path "  </tr>"
}
Add-Content $path "    </TR>"
Add-Content $path "  </table>"


################################################################
# PASSWORDING USING REVERSIBLE ENCRYPTION
Add-Content $path "		<table border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TH align=LEFT bgcolor = '#6F8487' style='color:white'>"
Add-Content $path "					 PASSWORD WITH REVERSING ENCRYPTION"
Add-Content $path "				</TH>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"

Add-Content $path "	<TABLE border = 0 style='width:100%'>"
Add-Content $path "	  <TR>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '40%'>"
Add-Content $path "	      NAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      SAMACCOUNTNAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      REVERSIBLE PASSWORD"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:black' WIDTH = '20%'>"
Add-Content $path "	      ENABLED"
Add-Content $path "	    </TH>"
Add-Content $path "	  </TR>"

foreach ($user in $UsersReverseEncrypt)
{
    $userNome = $user.Nome
    $userConta = $user.SamAccountName
    $userRP = $user.ReversePassword
    $userEnabled = $admin.Enabled
    Add-Content $path "  <tR>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '30%'>"
    Add-Content $path "      $userNome"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
    Add-Content $path "      $userConta"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '20%'>"
    Add-Content $path "      $userRP"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
    Add-Content $path "      $userEnabled"
    Add-Content $path "    </td>"
    Add-Content $path "  </tr>"
}
Add-Content $path "    </TR>"
Add-Content $path "  </table>"


################################################################
# DOES NOT REQUIRES KERBEROS PRE-AUTH
Add-Content $path "		<table border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TH align=LEFT bgcolor = '#6F8487' style='color:white'>"
Add-Content $path "					 DOESN'T REQUIRES KERBEROS PRE-AUTH"
Add-Content $path "				</TH>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"

Add-Content $path "	<TABLE border = 0 style='width:100%'>"
Add-Content $path "	  <TR>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '40%'>"
Add-Content $path "	      NAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      SAMACCOUNTNAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      NOT REQUIRE PRE-AUTH"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:black' WIDTH = '20%'>"
Add-Content $path "	      ENABLED"
Add-Content $path "	    </TH>"
Add-Content $path "	  </TR>"

foreach ($user in $UsersAsRepRoasting)
{
    $userNome = $user.Nome
    $userConta = $user.SamAccountName
    $userKRB = $user.DoesNotRequirePreAuth
    $userEnabled = $admin.Enabled
    Add-Content $path "  <tR>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '30%'>"
    Add-Content $path "      $userNome"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
    Add-Content $path "      $userConta"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '20%'>"
    Add-Content $path "      $userKRB"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
    Add-Content $path "      $userEnabled"
    Add-Content $path "    </td>"
    Add-Content $path "  </tr>"
}

################################################################
# SID HISTORY

Add-Content $path "		<table border = 0 style='width:100%'>"
Add-Content $path "			<TR>"
Add-Content $path "				<TH align=LEFT bgcolor = '#6F8487' style='color:white'>"
Add-Content $path "					 USERS WITH SID HISTORY"
Add-Content $path "				</TH>"
Add-Content $path "			</TR>"
Add-Content $path "		</TABLE>"

Add-Content $path "	<TABLE border = 0 style='width:100%'>"
Add-Content $path "	  <TR>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '40%'>"
Add-Content $path "	      NAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      SAMACCOUNTNAME"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:BLACK' WIDTH = '20%'>"
Add-Content $path "	      SID HISTORY"
Add-Content $path "	    </TH>"
Add-Content $path "	    <TH align=center bgcolor = '#95A2A4' style='color:black' WIDTH = '20%'>"
Add-Content $path "	      ENABLED"
Add-Content $path "	    </TH>"
Add-Content $path "	  </TR>"

foreach ($user in $UserSidHist)
{
    $userNome = $user.Nome
    $userConta = $user.SamAccountName
    $userSID = $user.DoesNotRequirePreAuth
    $userEnabled = $admin.Enabled
    Add-Content $path "  <tR>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '30%'>"
    Add-Content $path "      $userNome"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
    Add-Content $path "      $userConta"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '20%'>"
    Add-Content $path "      $userSID"
    Add-Content $path "    </td>"
    Add-Content $path "    <td align=center bgcolor = 'WHITE' style='color:BLACK' WIDTH = '15%'>"
    Add-Content $path "      $userEnabled"
    Add-Content $path "    </td>"
    Add-Content $path "  </tr>"
}



Add-Content $path "    </TR>"
Add-Content $path "  </table>"


######################################
# END HTML DETAILS
Add-Content $path "	  </BODY>"
Add-Content $path "	</HTML>"

###############################################################################################
###############################################################################################
###############################################################################################
#CALCULATE RISKS

$RiskOverall = 0


##################################################################################################
# CALCULATE RISKS ASREPROASTING

$RiskDesc_AsRep = "AS-REP Roasting is an attack against Kerberos for user accounts that do not require preauthentication. <p>If preauthentication is disabled, an attacker could request authentication data for any user and the DC would return an encrypted TGT that can be brute-forced offline."
if($CountAsRepRoasting -eq 0)
{
    $Risk_AsRep = "0"
    $RiskDesc_AsRep = "<span style='color: GREEN'>No Risk Found with AS-REP ROASTING </SPAN>"
}
elseif($CountAsRepRoasting -gt 0 -and $CountAsRepRoasting -le 4)
{
    $Risk_AsRep = "50"
    $RiskOverall = 29
}
else
{
    $Risk_AsRep = "100"
    $RiskOverall = 33
}

##################################################################################################
# CALCULATE RISKS userAccountControl Password Not Required

$RiskDesc_PassNotReq = "Active Directory enables the storing of user passwords with reversible encryption, which is essentially the same as storing them in plain text. This was introduced in Windows Server 2000, but still exists in even the most recent versions.  According to Microsoft this was introduced to provide:<P><li>support for applications that use protocols that require the user's password for authentication.</li>"
if($CountPassNotRequired -eq 0)
{
    $Risk_PassNotReq = "0"
    $RiskDesc_PassNotReq = "<span style='color: GREEN'>No Risk Found with AS-REP ROASTING </SPAN>"
}
elseif($CountPassNotRequired -gt 0 -and $CountPassNotRequired -le 4)
{
    $Risk_PassNotReq= "50"
    $RiskOverall = $RiskOverall + 12
}
else
{
    $Risk_PassNotReq= "100"
    $RiskOverall = $RiskOverall + 20
}

##################################################################################################
# CALCULATE RISKS STOREGED PASSWORD REVERSIBLE ENCRYPTION

$RiskDesc_RevEnc = "Active Directory enables the storing of user passwords with reversible encryption, which is essentially the same as storing them in plain text. This was introduced in Windows Server 2000, but still exists in even the most recent versions.  According to Microsoft this was introduced to provide:<P><li>support for applications that use protocols that require the user's password for authentication.</li>"
if($CountReversibleEncrypt -eq 0)
{
    $Risk_RevEnc = "0"
    $RiskDesc_RevEnc = "<span style='color: GREEN'>No Risk Found with users storing Reversible Encryption </SPAN>"
}
elseif($CountReversibleEncrypt -gt 0 -and $CountReversibleEncrypt -le 4)
{
    $Risk_RevEnc= "50"
    $RiskOverall = $RiskOverall + 12
}
else
{
    $Risk_RevEnc= "100"
    $RiskOverall = $RiskOverall + 20
}

##################################################################################################
# CALCULATE RISKS SID HISTORY

$RiskDesc_SidHist = "SID History is a very important attribute to support migration scenarios between Domains. <p>But it can be used as Persistence in some attacks. A adversary can add the SID History to some user to get persist privileges and that way it doesn't show up inside Privileged Groups.<p>Kinds of SIDHistory used to persistence:<p><li>S-1-5-21domain-512 - Domain Admins</li><li>S-1-5-21domain-518 - Schema Admins</li><li>S-1-5-21domain-519 - Enterprise Admins</li><li>S-1-5-32-544 - Administrators</li><li>S-1-5-21domain-512 - Domain Admins</li>"
if($totaluserssid -eq 0)
{
    $Risk_SidHist = "0"
    $RiskDesc_SidHist = "<span style='color: GREEN'>No Risk Found with SID HISTORY </SPAN>"
}
elseif($totaluserssid -gt 0 -and $totaluserssid -le 4)
{
    $Risk_SidHist= "60"
    $RiskOverall = $RiskOverall + 12
}
else
{
    $Risk_SidHist= "100"
    $RiskOverall = $RiskOverall + 20

}

################################################################################
# RISK DC END OF LIFE
$obsoletDC = 0
$Risk_DCEOL = 0
foreach ($DC in $DomainControllers)
{
    $dcName = $dc.Name
    $dcIPv4 = $dc.IPv4Address
    $dcOS= $dc.OperatingSystem
    $dcRODC= $dc.IsReadOnly
    if($dc.IsReadOnly){$dcRODC = 'true'}else{$dcRODC = 'false'}
    $dcSite= $dc.Site
    $dcDomain = $dc.Domain
    $dcForest= $dc.Forest
    if($dcOS.Contains("2000") -or $dcOS.Contains("2003") -or $dcOS.Contains("2008") )
    {
        $obsoletDC ++
        $Risk_DCEOL = 100
        $RiskOverall = $Risk_DCEOL
    }
    if($Risk_DCEOL -ne 0)
    {
        $RiskDesc_DCEOL = "Domain Controllers running Obsolet version of Windows is a great Risk. <p> Attackers can compromise the whole domain because of a single Domain Controller with Unsupported Version of Windows."
    }
    else
    {
        $RiskDesc_DCEOL = "<span style='color: GREEN'>No Risk Found with the version of Operating Systems of Domain Controllers</span>"
    }
}


##################################################################################################
# CALCULATE RISKS PRIVILEGED USERS

$RiskDesc_PrivUsers = "Too much Privileged Users found. We recomend that the number of Privileged Users must be the minimum necessary.<p>All Privileged Users must have their account segregated from Commom Users.<p>Privileged Users must have two accounts:<p><li>One Account for Day-to-Day baises.</li><li>One Second Account for Administrative Porposes.</li>"
$Perc_PrivUsers = [math]::round((($numberprivilegedusers / $numberofusers) * 100))
if($numberprivilegedusers -le 20)
{
    $Risk_PrivUsers = $numberprivilegedusers
    $RiskDesc_PrivUsers = "<span style='color: GREEN'>No Risk Found - The number of privileged users is good.</span>"
    $RiskOverall = $RiskOverall + 7
}
elseif ($numberprivilegedusers -gt 20 -and $numberprivilegedusers -le 40)
{
       $Risk_PrivUsers = $numberprivilegedusers
       $RiskDesc_PrivUsers = "<span style='color: GREEN'>No Risk Found - The number of privileged users is good.</span>"
       $RiskOverall = $RiskOverall + 10
   
}
elseif ($numberprivilegedusers -gt 40 -and $numberprivilegedusers -le 60)
{
    $Risk_PrivUsers = $numberprivilegedusers
    $RiskOverall = $RiskOverall + 18
}
elseif ($numberprivilegedusers -gt 60)
{
    $Risk_PrivUsers = 100
    $RiskOverall = $RiskOverall + 30
}

##################################################################################################
# CALCULATE RISKS USER KRBGTG LAST CHANGE PASSWORD

$krbtgtchange = get-aduser -identity krbtgt -properties passwordlastset #| ft passwordlastset
$Date60 = (Get-Date).AddDays(-60)
$Date180 = (Get-Date).AddDays(-182)
$Date365 = (Get-Date).AddDays(-365)
$Date548 = (Get-Date).AddDays(-548)
$Date730 = (Get-Date).AddDays(-730)
$KRBTGT_date = $krbtgtchange.PasswordLastSet
$Risk_krbtgt = "0"
$RiskDesc_KRBTGT = "<span style='color: GREEN'>No Risk Found with KRBTGT user </span>"
if ($KRBTGT_date -ge $date60)
{
    $Risk_krbtgt = "5"
    $RiskDesc_KRBTGT = "The KDC encrypts a user's TGT with a key it derives from the password of the krbtgt AD domain account. The krbtgt account and its password are shared between the KDC services of all DCs in a domain. <p>The Hash of KRBTGT account can be used in attacks to create Forged Tickets, like Gonden Tickets.<p>One way to help mitigate the risk of a bad actor using a compromised krbtgt key to forge user tickets is by periodically resetting the krbtgt account password. Resetting this password on a regular basis reduces the useful lifetime of krbtgt keys, in case one or more of them is compromised.<P>We recomend change the password of KRBTGT account each 6 months.<p> <small>Password Last Changed:</small><span style='color: red'> $KRBTGT_date </span>"
    $RiskOverall += 3
}
elseif ($KRBTGT_date -gt $Date60 -and $KRBTGT_date -le $date180)
{
    $Risk_krbtgt = "20"
    $RiskDesc_KRBTGT = "The KDC encrypts a user's TGT with a key it derives from the password of the krbtgt AD domain account. The krbtgt account and its password are shared between the KDC services of all DCs in a domain. <p>The Hash of KRBTGT account can be used in attacks to create Forged Tickets, like Gonden Tickets.<p>One way to help mitigate the risk of a bad actor using a compromised krbtgt key to forge user tickets is by periodically resetting the krbtgt account password. Resetting this password on a regular basis reduces the useful lifetime of krbtgt keys, in case one or more of them is compromised.<P>We recomend change the password of KRBTGT account each 6 months.<p> <small>Password Last Changed:</small><span style='color: red'> $KRBTGT_date </span>"
    $RiskOverall += 6
}
elseif ($KRBTGT_date -gt $Date180 -and $KRBTGT_date -le $date365)
{
    $Risk_krbtgt = "35"
    $RiskDesc_KRBTGT = "The KDC encrypts a user's TGT with a key it derives from the password of the krbtgt AD domain account. The krbtgt account and its password are shared between the KDC services of all DCs in a domain. <p>The Hash of KRBTGT account can be used in attacks to create Forged Tickets, like Gonden Tickets.<p>One way to help mitigate the risk of a bad actor using a compromised krbtgt key to forge user tickets is by periodically resetting the krbtgt account password. Resetting this password on a regular basis reduces the useful lifetime of krbtgt keys, in case one or more of them is compromised.<P>We recomend change the password of KRBTGT account each 6 months.<p> <small>Password Last Changed:</small><span style='color: red'> $KRBTGT_date </span>"
    $RiskOverall += 9
}
elseif ($KRBTGT_date -gt $Date365 -and $KRBTGT_date -le $date548)
{
    $Risk_krbtgt = "50"
    $RiskDesc_KRBTGT = "The KDC encrypts a user's TGT with a key it derives from the password of the krbtgt AD domain account. The krbtgt account and its password are shared between the KDC services of all DCs in a domain. <p>The Hash of KRBTGT account can be used in attacks to create Forged Tickets, like Gonden Tickets.<p>One way to help mitigate the risk of a bad actor using a compromised krbtgt key to forge user tickets is by periodically resetting the krbtgt account password. Resetting this password on a regular basis reduces the useful lifetime of krbtgt keys, in case one or more of them is compromised.<P>We recomend change the password of KRBTGT account each 6 months.<p> <small>Password Last Changed:</small><span style='color: red'> $KRBTGT_date </span>"
    $RiskOverall += 12
}
elseif ($KRBTGT_date -gt $Date548 -and $KRBTGT_date -le $date730)
{
    $Risk_krbtgt = "75"
    $RiskDesc_KRBTGT = "The KDC encrypts a user's TGT with a key it derives from the password of the krbtgt AD domain account. The krbtgt account and its password are shared between the KDC services of all DCs in a domain. <p>The Hash of KRBTGT account can be used in attacks to create Forged Tickets, like Gonden Tickets.<p>One way to help mitigate the risk of a bad actor using a compromised krbtgt key to forge user tickets is by periodically resetting the krbtgt account password. Resetting this password on a regular basis reduces the useful lifetime of krbtgt keys, in case one or more of them is compromised.<P>We recomend change the password of KRBTGT account each 6 months.<p> <small>Password Last Changed:</small><span style='color: red'> $KRBTGT_date </span>"
    $RiskOverall += 15
}
elseif ($KRBTGT_date -lt $Date730)
{
    $Risk_krbtgt = "100"
    $RiskDesc_KRBTGT = "The KDC encrypts a user's TGT with a key it derives from the password of the krbtgt AD domain account. The krbtgt account and its password are shared between the KDC services of all DCs in a domain. <p>The Hash of KRBTGT account can be used in attacks to create Forged Tickets, like Gonden Tickets.<p>One way to help mitigate the risk of a bad actor using a compromised krbtgt key to forge user tickets is by periodically resetting the krbtgt account password. Resetting this password on a regular basis reduces the useful lifetime of krbtgt keys, in case one or more of them is compromised.<P>We recomend change the password of KRBTGT account each 6 months.<p> <small>Password Last Changed:</small><span style='color: red'> $KRBTGT_date </span>"
    $RiskOverall += 20
}
##############################################################
#RISK OVERALL
if ($RiskOverall -le 19)
{
    $RiskDesc_Overall = "To low issues was found in the domain.<p>Keep doing a Good Job."
}
elseif($RiskOverall -gt 19 -and $RiskOverall -le 59)
{
    $RiskDesc_Overall = "Several vulnerabilities were found in the domain assessment.<p>We recommend that you fix the vulnerabilities as soon as possible.<p>These problems make Active Directory susceptible to attacks and by reducing exposure the environment will be more secure."
}
elseif ($RiskOverall -gt 59 -and $RiskOverAll-le 100)
{
    $RiskDesc_Overall = "Several vulnerabilities were found in the domain assessment.<p>We recommend that you fix the vulnerabilities as soon as possible.<p>These problems make Active Directory susceptible to attacks and by reducing exposure the environment will be more secure."
}
elseif ($RiskOverall -ge 100)
{
    $RiskOverall = 100
    $RiskDesc_Overall = "Several vulnerabilities were found in the domain assessment.<p>We recommend that you fix the vulnerabilities as soon as possible.<p>These problems make Active Directory susceptible to attacks and by reducing exposure the environment will be more secure."
}

###################################################################################################
# CREATE HTML RISKS

$path = $savepath + "\" + $filename_RISK

############################################
# CREATE CHARTS
############################################
Set-Content $path '<html>'
Add-Content $path '	<HEAD>'
Add-Content $path '	    <TITLE> DOMAIN ASSESSMENT </TITLE>'
############################################
# CREATE RISK CHART
Add-Content $path '	    <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>'
Add-Content $path '	    <script type="text/javascript">'
Add-Content $path "	    google.charts.load('current', {'packages':['gauge']});"

########################################################	  
# CHART GAUGE RISK TOTAL
Add-Content $path '	    google.charts.setOnLoadCallback(gaugeRiskTot);'
Add-Content $path '	    function gaugeRiskTot()'
Add-Content $path '	    {'
Add-Content $path '			var data = google.visualization.arrayToDataTable(['
Add-Content $path "				['Label', 'Value'],"
Add-Content $path "	    		['RISK', $RiskOverall],"
Add-Content $path '	    	]);'
Add-Content $path '	    	var options = {'
Add-Content $path '	    		width: 250, height: 250,'
Add-Content $path '	    		redFrom: 60, redTo: 100,'
Add-Content $path '	    		yellowFrom:20, yellowTo: 60,'
Add-Content $path '	    		greenFrom:0, greenTo: 20,'
Add-Content $path '	    		minorTicks: 5'
Add-Content $path '	    	};'
Add-Content $path "	    	var chart = new google.visualization.Gauge(document.getElementById('gaugeRiskTot'));"
Add-Content $path '	    	chart.draw(data, options);'
Add-Content $path '	    }'

########################################################	  
# CHART GAUGE RISK TO MUCH PRIVILEGED USERS
Add-Content $path '	    google.charts.setOnLoadCallback(gaugePriv);'
Add-Content $path '	    function gaugePriv()'
Add-Content $path '	    {'
Add-Content $path '	    	var data = google.visualization.arrayToDataTable(['
Add-Content $path "	    		['Label', 'Value'],"
Add-Content $path "	    		['PRIV', $Risk_PrivUsers],"
Add-Content $path '	    	]);'
Add-Content $path '	    	var options = {'
Add-Content $path "	    		width: 200, height: 200,"
Add-Content $path '	        	redFrom: 60, redTo: 100,'
Add-Content $path '	        	yellowFrom:20, yellowTo: 60,'
Add-Content $path '	    		greenFrom:0, greenTo: 20,'
Add-Content $path "	        	minorTicks: 5"
Add-Content $path '	      	};'
Add-Content $path "	        var chart = new google.visualization.Gauge(document.getElementById('gaugePriv'));"
Add-Content $path '	        chart.draw(data, options);'
Add-Content $path '	    }'

########################################################	  
# CHART GAUGE RISK SID HISTORY
Add-Content $path '	    google.charts.setOnLoadCallback(gaugeSid);'
Add-Content $path '	    function gaugeSid()'
Add-Content $path '	    {'
Add-Content $path '	    	var data = google.visualization.arrayToDataTable(['
Add-Content $path "	    		['Label', 'Value'],"
Add-Content $path "	            ['SID', $Risk_SidHist]," 
Add-Content $path '	        ]);'
Add-Content $path '	        var options = {'
Add-Content $path '	              width: 200, height: 200,'
Add-Content $path '	              redFrom: 60, redTo: 100,'
Add-Content $path '	              yellowFrom:20, yellowTo: 60,'
Add-Content $path '	    		  greenFrom:0, greenTo: 20,'
Add-Content $path '	              minorTicks: 5'
Add-Content $path '	            };'
Add-Content $path "	            var chart = new google.visualization.Gauge(document.getElementById('gaugeSid'));"
Add-Content $path '	            chart.draw(data, options);'
Add-Content $path '	          }'

########################################################	  
# CHART GAUGE RISK AS-REP-ROASTING
Add-Content $path '	    	  google.charts.setOnLoadCallback(gaugeRepRoast);'
Add-Content $path '	    	  function gaugeRepRoast()'
Add-Content $path '	    	  {'
Add-Content $path '	            var data = google.visualization.arrayToDataTable(['
Add-Content $path "	              ['Label', 'Value'],"
Add-Content $path "	              ['AS-REP', $RISK_AsRep],"
Add-Content $path '	            ]);'
Add-Content $path '	            var options = {'
Add-Content $path '	            	width: 200, height: 200,'
Add-Content $path '	            	redFrom: 60, redTo: 100,'
Add-Content $path '	            	yellowFrom:20, yellowTo: 60,'
Add-Content $path '	    			greenFrom:0, greenTo: 20,'
Add-Content $path '	            	minorTicks: 5'
Add-Content $path '	            };'
Add-Content $path "	            var chart = new google.visualization.Gauge(document.getElementById('gaugeRepRoast'));"
Add-Content $path '	            chart.draw(data, options);'
Add-Content $path '	          }'

########################################################	  
# CHART GAUGE RISK krbtg
Add-Content $path '	    	  google.charts.setOnLoadCallback(gaugeKRBTG);'
Add-Content $path '	    	  function gaugeKRBTG()'
Add-Content $path '	    	  {'
Add-Content $path '	            var data = google.visualization.arrayToDataTable(['
Add-Content $path "	              ['Label', 'Value'],"
Add-Content $path "	              ['KRBTGT', $RISK_krbtgt],"
Add-Content $path '	            ]);'
Add-Content $path '	            var options = {'
Add-Content $path '	              width: 200, height: 200,'
Add-Content $path '	              redFrom: 60, redTo: 100,'
Add-Content $path '	              yellowFrom:20, yellowTo: 60,'
Add-Content $path '	    		  greenFrom:0, greenTo: 20,'
Add-Content $path '	              minorTicks: 5'
Add-Content $path '	            };'
Add-Content $path "	            var chart = new google.visualization.Gauge(document.getElementById('gaugeKRBTG'));"
Add-Content $path '	            chart.draw(data, options);'
Add-Content $path '	          }'

########################################################	  
# CHART GAUGE RISK PassNotRequired
Add-Content $path '	    	  google.charts.setOnLoadCallback(gaugePassNotReq);'
Add-Content $path '	    	  function gaugePassNotReq()'
Add-Content $path '	    	  {'
Add-Content $path '	            var data = google.visualization.arrayToDataTable(['
Add-Content $path "	              ['Label', 'Value'],"
Add-Content $path "	              ['PASS', $RISK_PassNotReq],"
Add-Content $path '	            ]);'
Add-Content $path '	            var options = {'
Add-Content $path '	              width: 200, height: 200,'
Add-Content $path '	              redFrom: 60, redTo: 100,'
Add-Content $path '	              yellowFrom:20, yellowTo: 60,'
Add-Content $path '	    		  greenFrom:0, greenTo: 20,'
Add-Content $path '	              minorTicks: 5'
Add-Content $path '	            };'
Add-Content $path "	            var chart = new google.visualization.Gauge(document.getElementById('gaugePassNotReq'));"
Add-Content $path '	            chart.draw(data, options);'
Add-Content $path '	          }'

########################################################	  
# CHART GAUGE RISK REVERSIBLE ENCRYPTION
Add-Content $path '	    	  google.charts.setOnLoadCallback(gaugeRevEnc);'
Add-Content $path '	    	  function gaugeRevEnc()'
Add-Content $path '	    	  {'
Add-Content $path '	            var data = google.visualization.arrayToDataTable(['
Add-Content $path "	              ['Label', 'Value'],"
Add-Content $path "	              ['REVERSE', $Risk_RevEnc],"
Add-Content $path '	            ]);'
Add-Content $path '	            var options = {'
Add-Content $path '	              width: 200, height: 200,'
Add-Content $path '	              redFrom: 60, redTo: 100,'
Add-Content $path '	              yellowFrom:20, yellowTo: 60,'
Add-Content $path '	    		  greenFrom:0, greenTo: 20,'
Add-Content $path '	              minorTicks: 5'
Add-Content $path '	            };'
Add-Content $path "	            var chart = new google.visualization.Gauge(document.getElementById('gaugeRevEnc'));"
Add-Content $path '	            chart.draw(data, options);'
Add-Content $path '	          }'

########################################################	  
# CHART GAUGE RISK REVERSIBLE ENCRYPTION
Add-Content $path '	    	  google.charts.setOnLoadCallback(gaugeDCEOL);'
Add-Content $path '	    	  function gaugeDCEOL()'
Add-Content $path '	    	  {'
Add-Content $path '	            var data = google.visualization.arrayToDataTable(['
Add-Content $path "	              ['Label', 'Value'],"
Add-Content $path "	              ['OS - EOL', $Risk_DCEOL],"
Add-Content $path '	            ]);'
Add-Content $path '	            var options = {'
Add-Content $path '	              width: 200, height: 200,'
Add-Content $path '	              redFrom: 60, redTo: 100,'
Add-Content $path '	              yellowFrom:20, yellowTo: 60,'
Add-Content $path '	    		  greenFrom:0, greenTo: 20,'
Add-Content $path '	              minorTicks: 5'
Add-Content $path '	            };'
Add-Content $path "	            var chart = new google.visualization.Gauge(document.getElementById('gaugeDCEOL'));"
Add-Content $path '	            chart.draw(data, options);'
Add-Content $path '	          }'

#####################################

Add-Content $path '	        </script>'
Add-Content $path '		</head>'

#################################
# INICIO BODY HTML
# CABEÇALHO
Add-Content $path '		<BODY>'
Add-Content $path "			<table border = 0 style='width:100%'>"
Add-Content $path '	    		<TR>'
Add-Content $path "	    			<TD align=LEFT bgcolor = '#6F8487' style='color:white'>"
Add-Content $path "	    				<h2>ACTIVE DIRECTORY ASSESSMENT REPORT: <span style='color: #2EBED8'>$DomainName</span></H2>"
Add-Content $path '	    			</TD>'
Add-Content $path '	    		</TR>'
Add-Content $path '	    	</TABLE>'
Add-Content $path "	    	<TABLE border = 0 style='width:100%'>"
Add-Content $path '	    		<TR>'
Add-Content $path "	    			<TD  align=center bgcolor = '#95A2A4' style='color:white' WIDTH = '20%'>"
Add-Content $path "	    				<A HREF=$filename_ASS STYLE='COLOR:WHITE'><H2>GRÁFICOS</H2></A>"
Add-Content $path '	    			</TD>'
Add-Content $path "	    			<TD  align=center bgcolor = '#8EA1A4' style='color:white' WIDTH = '20%'>"
Add-Content $path "	    				<A HREF=$filename_DET STYLE='COLOR:WHITE'><H2>DETALHES</H2></A>"
Add-Content $path '	    			</TD>'
Add-Content $path "	    			<TD  align=center bgcolor = '#95A2A4' style='color:white' WIDTH = '20%'>"
Add-Content $path "	    				<A HREF=$filename_RISK STYLE='COLOR:WHITE bgcolor=#8EA1A4'><H2>RISCOS</H2></A>"
Add-Content $path '	    			</TD>'
Add-Content $path '	    		</TR>'
Add-Content $path '	    	</TABLE>'

##################################
# INICIO GRÁFICOS

Add-Content $path "	    	<TABLE border = 1 style='width:100%'>"
Add-Content $path "	    		<tr>"
Add-Content $path '	    			<th style="width: 25%; align=Center">'
Add-Content $path "	    				TOTAL RISK"
Add-Content $path "	    			</TH>"
Add-Content $path '	    			<th style="width: 75%; align=Center">'
Add-Content $path "	    				DESCRIPTION"
Add-Content $path "	    			</TH>"
Add-Content $path "	    		</tr>"
Add-Content $path "	    		<TR ALIGN=Center>"
Add-Content $path '	    			<TD valign=TOP style="width: 5%; align=Center">'
Add-Content $path '	    				<div id="gaugeRiskTot"></div>'
Add-Content $path "	    			</TD>"
Add-Content $path '	    			<td valign=TOP align=Left style="width: 75%; ">'
Add-Content $path "	    			$RiskDesc_Overall"
Add-Content $path "	    			</td>"
Add-Content $path "	    		</tr>"

#####################################
# CHART DOMAIN CONTROLLER OBSOLETO
Add-Content $path "	    	<TABLE border = 1 style='width:100%'>"
Add-Content $path "	    		<tr>"
Add-Content $path '	    			<th style="width: 25%; align=Center">'
Add-Content $path '	    				DOMAIN CONTROLLER - END OF LIFE'
Add-Content $path '	    			</TH>'
Add-Content $path '	    			<th style="width: 75%; align=Center">'
Add-Content $path '	    				DESCRIPTION'
Add-Content $path '	    			</TH>'
Add-Content $path '	    		</tr>'
Add-Content $path '	    		<TR ALIGN=Center>'
Add-Content $path '	    			<TD valign=TOP style="width: 5%; align=Center">'
Add-Content $path '	    				<div id="gaugeDCEOL"></div>'
Add-Content $path '	    			</TD>'
Add-Content $path '	    			<td valign=TOP align=Left style="width: 75%; ">'
Add-Content $path "	    				$RiskDesc_DCEOL"
Add-Content $path '	    			</td>'
Add-Content $path '	    		</tr>'
Add-Content $path '	    	</TABLE>'


#####################################
# CHART PRIVILEGED USERS
Add-Content $path "	    	<TABLE border = 1 style='width:100%'>"
Add-Content $path "	    		<tr>"
Add-Content $path '	    			<th style="width: 25%; align=Center">'
Add-Content $path '	    				PRIVILEGED USERS'
Add-Content $path '	    			</TH>'
Add-Content $path '	    			<th style="width: 75%; align=Center">'
Add-Content $path '	    				DESCRIPTION'
Add-Content $path '	    			</TH>'
Add-Content $path '	    		</tr>'
Add-Content $path '	    		<TR ALIGN=Center>'
Add-Content $path '	    			<TD valign=TOP style="width: 5%; align=Center">'
Add-Content $path '	    				<div id="gaugePriv"></div>'
Add-Content $path '	    			</TD>'
Add-Content $path '	    			<td valign=TOP align=Left style="width: 75%; ">'
Add-Content $path "	    				$RiskDesc_PrivUsers"
Add-Content $path '	    			</td>'
Add-Content $path '	    		</tr>'
Add-Content $path '	    	</TABLE>'

#####################################
# CHART SID HISTORY
Add-Content $path "	    	<TABLE border = 1 style='width:100%'>"
Add-Content $path '	    		<tr>'
Add-Content $path '	    			<th style="width: 25%; align=Center">'
Add-Content $path '	    				SID HISTORY'
Add-Content $path '	    			</TH>'
Add-Content $path '	    			<th style="width: 75%; align=Center">'
Add-Content $path '	    				DESCRIPTION'
Add-Content $path '	    			</TH>'
Add-Content $path '	    		</tr>'
Add-Content $path '	    		<TR ALIGN=Center>'
Add-Content $path '	    			<TD valign=TOP style="width: 5%; align=Center">'
Add-Content $path '	    				<div id="gaugeSid"></div>'
Add-Content $path '	    			</TD>'
Add-Content $path '	    			<td valign=TOP align=Left style="width: 75%; ">'
Add-Content $path "                   $RiskDesc_SidHist"
Add-Content $path '	    			</td>'
Add-Content $path '	    		</tr>'

#####################################
# CHART KRBTGT
Add-Content $path '	    		<tr>'
Add-Content $path '	    			<th style="width: 25%; align=Center">'
Add-Content $path '	    				USER KRBTGT'
Add-Content $path '	    			</TH>'
Add-Content $path '	    			<th style="width: 75%; align=Center">'
Add-Content $path '	    				DESCRIPTION'
Add-Content $path '	    			</TH>'
Add-Content $path '	    		</tr>'
Add-Content $path '	    		<TR ALIGN=Center>'
Add-Content $path '	    			<TD valign=TOP style="width: 20%; align=Center">'
Add-Content $path '	    				<div id="gaugeKRBTG"></div>'
Add-Content $path '	    			</TD>'
Add-Content $path '	    			<td valign=TOP align=Left style="width: 75%; ">'
Add-Content $path "	    				$RiskDesc_KRBTGT" 
Add-Content $path '	    			</td>'
Add-Content $path '	    		</tr>'

#####################################
# CHART AS-REP ROASTING
Add-Content $path '	    		<tr>'
Add-Content $path '	    			<th style="width: 25%; align=Center">'
Add-Content $path '	    				AS-REP-ROASTING'
Add-Content $path '	    			</TH>'
Add-Content $path '	    			<th style="width: 75%; align=Center">'
Add-Content $path '	    				DESCRIPTION'
Add-Content $path '	    			</TH>'
Add-Content $path '	    		</tr>'
Add-Content $path '	    		<TR ALIGN=Center>'
Add-Content $path '	    			<TD valign=TOP style="width: 20%; align=Center">'
Add-Content $path '	    				<div id="gaugeRepRoast"></div>'
Add-Content $path '	    			</TD>'
Add-Content $path '	    			<td valign=TOP align=Left style="width: 75%; ">'
Add-Content $path "	    				$RiskDesc_AsRep"
Add-Content $path '	    			</td>'
Add-Content $path '	    		</tr>'

#####################################
# CHART PASSWORD NOT REQUIRED
Add-Content $path '	    		<tr>'
Add-Content $path '	    			<th style="width: 25%; align=Center">'
Add-Content $path '	    				PASSWORD NOT REQUIRED'
Add-Content $path '	    			</TH>'
Add-Content $path '	    			<th style="width: 75%; align=Center">'
Add-Content $path '	    				DESCRIPTION'
Add-Content $path '	    			</TH>'
Add-Content $path '	    		</tr>'
Add-Content $path '	    		<TR ALIGN=Center>'
Add-Content $path '	    			<TD valign=TOP style="width: 20%; align=Center">'
Add-Content $path '	    				<div id="gaugePassNotReq"></div>'
Add-Content $path '	    			</TD>'
Add-Content $path '	    			<td valign=TOP align=Left style="width: 75%; ">'
Add-Content $path "	    			   $RiskDesc_PassNotReq"
Add-Content $path '	    			</td>'
Add-Content $path '	    		</tr>'

#####################################
# CHART REVERSIBLE PASSWORD
Add-Content $path '	    		<tr>'
Add-Content $path '	    			<th style="width: 25%; align=Center">'
Add-Content $path '	    				PASSWORD REVERSIBLE ENCRYPTION'
Add-Content $path '	    			</TH>'
Add-Content $path '	    			<th style="width: 75%; align=Center">'
Add-Content $path '	    				DESCRIPTION'
Add-Content $path '	    			</TH>'
Add-Content $path '	    		</tr>'
Add-Content $path '	    		<TR ALIGN=Center>'
Add-Content $path '	    			<TD valign=TOP style="width: 20%; align=Center">'
Add-Content $path '	    				<div id="gaugeRevEnc"></div>'
Add-Content $path '	    			</TD>'
Add-Content $path '	    			<td valign=TOP align=Left style="width: 75%; ">'
Add-Content $path "	    				$RiskDesc_RevEnc"
Add-Content $path '	    			</td>'
Add-Content $path '	    		</tr>'
Add-Content $path '	    	</TABLE>'

#####################################
# FIM HTML
Add-Content $path '	    	</BODY>'
Add-Content $path '	    </HTML>'
