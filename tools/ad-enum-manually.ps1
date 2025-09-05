function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    # Get the Primary DC (PDC) with PdcRoleOwer = ...
    $pdc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    # Get LDAP destinguied name
    $dn = ([adsi]'').distinguishedName
    # Build LDAP path
    $ldap = "LDAP://$pdc/$dn"
    # Search from LDAP domain root directory endpoint
    $direntry = New-Object System.DirectoryServices.DirectoryEntry($ldap)
    $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry, $LDAPQuery)
    return $dirsearcher.FindAll() 
}

function LDAPEnumUsers {
  return LDAPSearch("(objectcategory=user)") | % { $_.properties.cn};
}

function LDAPEnumGroups {
  return LDAPSearch("(objectcategory=group)") | % { $_.properties.cn};
}

function LDAPEnumGroupMembers {
  return LDAPSearch("(objectcategory=group)") | % { "[*] Group",$_.properties.cn,"[+] Members",$_.properties.member }
}

function LDAPSearchGroupMembers {
   param (
        [string]$LDAPGroup
   )
   
   return LDAPSearch("(&(objectCategory=group)(cn=$LDAPGroup))") | % { $_.Properties.member }
}

function LDAPSearchUser {
   param (
        [string]$LDAPUser
   )
   return LDAPSearch("(name=$LDAPUser)") | % { $_.properties | Format-Table }
}