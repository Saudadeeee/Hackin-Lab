<?php
/**
 * XPath & LDAP Lab · the in-memory directory that levels 6-10 search.
 *
 * Shape of an entry:
 *   ['dn' => '...', 'attrs' => ['uid' => ['alice'], 'objectClass' => ['top','person'], ...]]
 *
 * Attributes are multi-valued because LDAP attributes are multi-valued, and
 * because objectClass being a list is what makes level 8 interesting.
 *
 * Entry order matters. A directory server returns entries in whatever order it
 * finds them, and an application that "logs the user in as the first result"
 * inherits that order as a security decision. Here the system account was
 * provisioned first, so it is first - which is what makes the level 6 bypass
 * land on an administrator instead of on a random employee.
 */

/** How this directory stores passwords: {SHA} + base64(sha1(raw)). */
function xl_ldap_hash(string $password): string
{
    return '{SHA}' . base64_encode(sha1($password, true));
}

/** @return array<int,array{dn:string,attrs:array<string,array<int,string>>}> */
function xl_directory(): array
{
    static $entries = null;
    if ($entries !== null) {
        return $entries;
    }

    $entries = [
        [
            'dn'    => 'uid=root_admin,ou=system,dc=hackinlab,dc=internal',
            'attrs' => [
                'uid'            => ['root_admin'],
                'cn'             => ['Directory Administrator'],
                'sn'             => ['Administrator'],
                'objectClass'    => ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                'ou'             => ['system'],
                'role'           => ['administrator'],
                'mail'           => ['root_admin@hackinlab.internal'],
                'employeeNumber' => ['1'],
                'userPassword'   => [xl_ldap_hash('Wq7-zR4m-Tunnel-Grid')],
            ],
        ],
        [
            'dn'    => 'uid=awhitfield,ou=people,dc=hackinlab,dc=internal',
            'attrs' => [
                'uid'            => ['awhitfield'],
                'cn'             => ['Amara Whitfield'],
                'sn'             => ['Whitfield'],
                'objectClass'    => ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                'ou'             => ['people'],
                'role'           => ['staff'],
                'mail'           => ['awhitfield@hackinlab.internal'],
                'employeeNumber' => ['14'],
                'userPassword'   => [xl_ldap_hash('Harbour-Kestrel-14')],
            ],
        ],
        [
            'dn'    => 'uid=dkoval,ou=people,dc=hackinlab,dc=internal',
            'attrs' => [
                'uid'            => ['dkoval'],
                'cn'             => ['Dmytro Koval'],
                'sn'             => ['Koval'],
                'objectClass'    => ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                'ou'             => ['people'],
                'role'           => ['staff'],
                'mail'           => ['dkoval@hackinlab.internal'],
                'employeeNumber' => ['23'],
                'userPassword'   => [xl_ldap_hash('Slate-Meridian-23')],
            ],
        ],
        [
            'dn'    => 'uid=lmoreau,ou=people,dc=hackinlab,dc=internal',
            'attrs' => [
                'uid'            => ['lmoreau'],
                'cn'             => ['Lucie Moreau'],
                'sn'             => ['Moreau'],
                'objectClass'    => ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                'ou'             => ['people'],
                'role'           => ['staff'],
                'mail'           => ['lmoreau@hackinlab.internal'],
                'employeeNumber' => ['31'],
                'userPassword'   => [xl_ldap_hash('Cobalt-Lantern-31')],
            ],
        ],
        [
            'dn'    => 'uid=pnakamura,ou=people,dc=hackinlab,dc=internal',
            'attrs' => [
                'uid'            => ['pnakamura'],
                'cn'             => ['Priya Nakamura'],
                'sn'             => ['Nakamura'],
                'objectClass'    => ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                'ou'             => ['people'],
                'role'           => ['staff'],
                'mail'           => ['pnakamura@hackinlab.internal'],
                'employeeNumber' => ['42'],
                'userPassword'   => [xl_ldap_hash('Driftwood-Pike-42')],
            ],
        ],
        [
            // A bind account. Not in ou=people, so nobody browsing the staff
            // directory would ever see it - until a wildcard removes the filter.
            'dn'    => 'uid=svc_ldapsync,ou=services,dc=hackinlab,dc=internal',
            'attrs' => [
                'uid'          => ['svc_ldapsync'],
                'cn'           => ['Replication Bind Account'],
                'objectClass'  => ['top', 'account', 'simpleSecurityObject'],
                'ou'           => ['services'],
                'role'         => ['service'],
                'description'  => ['replication bind account, do not expose to the staff directory'],
                'mail'         => ['ops@hackinlab.internal'],
                'userPassword' => [xl_ldap_hash('Nightly-Rsync-7Kd')],
            ],
        ],
        [
            // objectClass has no "person" in it. That is what the level 8
            // filter is relying on to keep this entry out of staff search.
            'dn'    => 'uid=vault_agent,ou=services,dc=hackinlab,dc=internal',
            'attrs' => [
                'uid'         => ['vault_agent'],
                'cn'          => ['Secrets Vault Agent'],
                'objectClass' => ['top', 'applicationProcess'],
                'ou'          => ['services'],
                'role'        => ['service'],
                'description' => ['issues short-lived credentials to build jobs'],
                'authToken'   => ['VA-TKN-51D9C2'],
                'mail'        => ['vault@hackinlab.internal'],
            ],
        ],
        [
            // A person, so it survives every objectClass filter in the lab.
            // The recoveryKey is the level 9 target: six characters, a-z0-9.
            'dn'    => 'uid=svc_rotate,ou=services,dc=hackinlab,dc=internal',
            'attrs' => [
                'uid'          => ['svc_rotate'],
                'cn'           => ['Key Rotation Operator'],
                'sn'           => ['Rotate'],
                'objectClass'  => ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
                'ou'           => ['services'],
                'role'         => ['service'],
                'mail'         => ['rotate@hackinlab.internal'],
                'description'  => ['rotates directory signing keys on the first of the month'],
                'recoveryKey'  => ['m2v7qd'],
                'userPassword' => [xl_ldap_hash('Rotate-Vanta-Ridge')],
            ],
        ],
    ];

    return $entries;
}

/** Find one entry by uid, or null. Used by the levels to describe their goal. */
function xl_entry(string $uid): ?array
{
    foreach (xl_directory() as $e) {
        if (strcasecmp($e['attrs']['uid'][0] ?? '', $uid) === 0) {
            return $e;
        }
    }
    return null;
}
