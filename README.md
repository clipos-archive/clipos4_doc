# Overview of CLIP OS 4

[CLIP OS](https://clip-os.org) is a GNU/Linux meta-distribution designed with the following hypotheses in mind:
* everyone (developer, administrator, end user) is fallible and can commit hazardous actions by mistake;
* all code can contain vulnerabilities, which means that we must take into account the threat, minimize it (e.g., shrink the attack surface), identify potential residual vulnerabilities, and be able to deploy over-the-air updates;
* only trusted code should be executable (no arbitrary code execution nor persistence);
* we consider that there are multiple administrator roles, according to organizational measures or to limit privileges available to one person;
* the system can have multiple authorized users;
* the system can be connected to untrusted networks (e.g., in a road warrior environment);
* log events should be available to detect attacks or misbehavior;
* and multiple user environments can manage data of different sensitivities: *low* (e.g., Internet) and *high* (private network).

To achieve these requirements, CLIP OS provides multiple security enhancements such as process isolation, tailored permission model, and multiple hardening developments deeply integrated into the system.
There are currently two main use cases to the CLIP OS project, each one provided by a dedicated CLIP OS species: an end user system targeting common office tasks, and a VPN gateway.

CLIP OS started in 2005 and is now publicly developed with the [version 5](https://github.com/clipos).
This version 4 of CLIP OS is not intended to be used as is.
Some packages may be missing and others may be incomplete because of the initial publication process.
However, as for the version 5, you are free to pick any components or patches (according to their license terms) that may fit your needs.

## Development, packaging and update

CLIP OS is based on [Gentoo Hardened](https://wiki.gentoo.org/wiki/Hardened_Gentoo), which comes with a [hardened toolchain](https://wiki.gentoo.org/wiki/Hardened/Toolchain) and multiple security enhancements.
Thus the package manager on the developer side is Portage, but the resulting builds for a CLIP OS distribution are shipped with Debian packages thanks to a [custom wrapper](https://github.com/clipos-archive/src_platform_clip-deb).
Two [signatures](https://github.com/clipos-archive/src_platform_gen-crypt), with a CLIP OS-specific format, are appended to each Debian package: one for the developer and another for a controller, thus allowing a two-level sign-off on every update.
The [update mechanism](https://github.com/clipos-archive/src_platform_clip-install-clip) is fully automated and run in the background in a dedicated VServer container.
The [critical system components](https://github.com/clipos-archive/clipos4_portage-overlay-clip/blob/master/clip-conf/clip-core-conf) (e.g., kernel, update mechanism, user management, network configuration, etc.) are updated following the [A/B update principle](https://source.android.com/devices/tech/ota/ab/) with two different partition sets updated alternatively.
This ensures that the system remains bootable and recoverable if a critical update fails or is interrupted.
An on-the-fly update can be applied for [non-critical components](https://github.com/clipos-archive/clipos4_portage-overlay-clip/blob/master/clip-conf/rm-apps-conf) (e.g., user applications), thus not requiring a reboot for minor updates but still being able to automatically rollback if an error occurs.

Multiple packages are patched to fit the needs of CLIP OS.
These modifications can be found in [portage-overlay](https://github.com/clipos-archive/clipos4_portage-overlay) (identified with [USE flags](https://github.com/clipos-archive/clipos4_portage-overlay-clip/blob/master/profiles/use.desc)), and custom (and imported) developments are packaged in [portage-overlay-clip](https://github.com/clipos-archive/clipos4_portage-overlay-clip).
The related sources are listed in the Repo [manifest](https://github.com/clipos-archive/clipos4_manifest).

## Partitioning and hardening of services

CLIP OS uses a lot of containers (internally called *jails*), following the defense in depth principle, thanks to [Linux-VServer](http://www.linux-vserver.org) features.
Linux-VServer is a kernel patch which leverages Linux namespaces to create secure partitioning of processes.
Among other things, it allows to tag processes, resources and networks with context identifiers (XIDs) and network identifiers (NIDs).
It also adds a local network per jail (with no NIC), PTS restrictions, multiple `/proc` visibility restrictions, WATCH (audit) and ADMIN roles, reduces covert channels, and adds multilevel restrictions.
CLIP OS does not use the upstream VServer userspace tools but a minimal and security-focused [vsctl](https://github.com/clipos-archive/src_platform_vsctl).
A sample jail configuration can be found for a [user jail](https://github.com/clipos-archive/src_platform_clip-vserver/blob/master/jails/rm_b) or a [web server jail](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/www-servers/nginx/files/clip/rb/jail).

Multiple [jail layouts](https://github.com/clipos-archive/clipos4_portage-overlay-clip/blob/master/clip-layout), mostly read-only, are used for [system services](https://github.com/clipos-archive/src_platform_core-services/blob/master/jails).
The content of each jail is minimal to reduce the tools available to attackers (e.g., [BusyBox](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/sys-apps/busybox/busybox-1.25.1-r1.ebuild#L82)).
Communications between jails are handled through secure IPC (e.g., UNIX sockets or SSH on the [local loop](https://github.com/clipos-archive/src_platform_clip-patches/blob/master/2002_loopback_classB.patch)).
[Firewall rules](https://github.com/clipos-archive/src_platform_clip-generic-net/blob/master/lib/netfilter) control all network accesses (e.g., local loop, Ethernet, Wi-Fi, UMTS, etc.).
Moreover, critical services are hardened with custom patches: [strongSwan](https://github.com/clipos-archive/src_platform_strongswan-patches), [Syslog-NG](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/app-admin/syslog-ng/files/syslog-ng-3.4.7-clip-jail.patch), [DHCP client](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/net-misc/dhcpcd/files/dhcpcd-6.4.7-clip.patch), [Nginx](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/www-servers/nginx/files/nginx-1.7.6-clip-chroot.patch), etc.

To help create these containers and reduce privileges, CLIP OS provides libraries of security helpers: [clip-lib](https://github.com/clipos-archive/src_platform_clip-lib) (secure privilege management) and [clip-libvserver](https://github.com/clipos-archive/src_platform_clip-libvserver) (container management).

## CLIP-LSM and custom Linux patches

[CLIP-LSM](https://github.com/clipos-archive/src_platform_clip-lsm) is a custom Linux Security Module enhancing the Linux permission model (capabilities), adding extra VServer permissions (e.g., IPsec enforcement) and leveraging hardening features from [PaX](https://pax.grsecurity.net) and [grsecurity](https://grsecurity.net).
Multiple other [Linux patches](https://github.com/clipos-archive/src_platform_clip-patches) fix some issues and add miscellaneous security features.

Root and kernel-spawned processes are restricted through an extra capability bounding set, a limited enforcement of root setuid bits and a strict Trusted Path Execution.

[Devctl](https://github.com/clipos-archive/src_platform_clip-lsm/blob/master/security/clsm/devctl.c) is a mechanism providing extended device access control, e.g., to lock security-relevant mount options, and enforce mandatory device and mount access control (read, write and execute).

[Veriexec](https://github.com/clipos-archive/src_platform_clip-lsm/blob/master/security/clsm/veriexec.c) is a simple right management system (inspired from NetBSD) which also checks files integrity.
The [configuration](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/sys-apps/coreutils/coreutils-8.20-r2.ebuild#L193) is independent from the target file(-system) and enables easy on-the-fly updates thanks to the [verictl](https://github.com/clipos-archive/src_platform_verictl) tool.
Veriexec handles [extra rights](https://github.com/clipos-archive/src_platform_clip-lsm/blob/master/include/linux/clip_lsm.h) per jail, either to add extra access control for operations which are allowed by default on a vanilla kernel (e.g., network access or specific IPsec-related operations), or provide a limited way to allow certain operations that usually require extensive capabilities (e.g., kernel log access).
It is also in charge of granting some permission to scripts, according to a composition of effective, inherited and permissive flags.

One of the basic principles of CLIP OS is the enforcement of a "write *xor* execute" policy, both at the memory management level and with regards to filesystem access rights.
This means that a process should not be allowed to execute something not provided by the system, thus avoiding arbitrary code execution and persistent attacks.
The main goal is to protect the kernel by restricting arbitrary syscalls that an attacker could perform with a crafted binary or certain script languages.
It also improves the multilevel isolation by reducing the ability of an attacker to use side channels with specific code.
These restrictions can natively be enforced for ELF binaries (with the `noexec` mount option) but require a kernel patch to properly handle scripts (e.g., Python, Perl).
A new open flag ([O\_MAYEXEC](https://github.com/clipos-archive/src_platform_clip-patches/blob/master/1901_open_mayexec.patch)) is then used by [modified interpreters](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/dev-lang/perl/files/perl-5.16.3-clip-mayexec.patch).

Since the chroot syscall is used as a secondary isolation mechanism, to further isolate some processes within a given VServer container, some extra restrictions on chroot are also enforced: FD leak and access safeguards, ptrace restrictions, integration with grsecurity and VServer, etc.

## Multilevel security

CLIP OS can be used as a [multilevel](https://en.wikipedia.org/wiki/Multilevel_security) operating system, which helps handle data of different sensitivities on the same system, and can limit data leak.
The end user can use two desktop environments: a *low* level (called `RM_B`) connected to Internet and a *high* level (called `RM_H`) to deal with sensitive data, only accessible through a VPN (IPsec).
Each environment contains usual applications (e.g., web browser, office suite, graphic software) which are confined to their assigned level (e.g., network, files, GUI).

Multiple components must be aware of this security model, enforce it, and enable the [end user to manage multiple levels](https://www.ssi.gouv.fr/uploads/2018/04/salaun-m_these_manuscrit.pdf):
* display levels to user ([window manager](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/x11-wm/openbox/files/openbox-3.5.0-clip-domains.patch) and [trusted panel](https://github.com/clipos-archive/clipos4_portage-overlay-clip/blob/master/x11-misc));
* secure and trusted GUI isolation ([GUI domains](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/x11-base/xorg-server/files/xorg-server-1.19.3-clip-domains.patch) and [VNC viewers](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/net-misc/tigervnc));
* black and red diodes ([cryptd](https://github.com/clipos-archive/src_platform_cryptd) and [cryptclt](https://github.com/clipos-archive/src_platform_cryptclt)) to push or decrypt files from the *low* to the *high* level (following the [Bell-LaPadula model](https://en.wikipedia.org/wiki/Bell%E2%80%93LaPadula_model)), or encrypt files from the *high* to the *low* level;
* VServer levels;
* external mass storage signature and data encryption;
* and multilevel [smartcard proxy](https://github.com/caml-pkcs11/caml-crush).

CLIP OS can also handle external devices per jail: a scanner, a printer, a webcam, a sound card and a smartcard.

## Admin and audit roles

A CLIP OS user account can be configured with a composition of privileged roles: administrator (admin) and auditor (audit).
It is important to note that the privilege delegation for these roles is not based on granting partial or total root privileges (i.e. no `sudo` or equivalent), but on read and/or write access to specific configuration files within the VServer container dedicated to each role.
Modified configuration files are then securely parsed, and applied if valid, by privileged daemons outside of those containers.

The goal of the admin role is to configure the system.
However, such a role must not be able to tamper with the system nor to access other user's data.
CLIP OS is designed to grant these accesses to the administrator:
* devices visibility management;
* time and date configuration;
* user management ([userd](https://github.com/clipos-archive/src_platform_userd));
* networking and IPsec management ([clip-netd](https://github.com/clipos-archive/src_platform_clip-netd));
* display configuration;
* optional packages (e.g., user applications) installation and uninstallation;
* and system update configuration ([downloadrequest](https://github.com/clipos-archive/src_platform_downloadrequest)), but not package signature authorities.

The audit role is used to gather information from the system, but without the ability to access any configuration not related to system logs.
Log events are only accessible to this role, but in a read-only way.
Log management (e.g., storage limits, remote transfers) is exclusively allowed to the audit role.

These roles can be used through dedicated GUIs (e.g., [clip-config](https://github.com/clipos-archive/src_platform_clip-config)), or CLIs and files.
This may be available locally by a logged user, or through a dedicated VPN via an SSH session.

## Authentication and cryptography

We use a hardened system password manager ([PAM tcb](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/sys-apps/tcb) from Openwall) with the bcrypt hashing algorithm.
On embedded devices, users are automatically jailed in the appropriate VServer container when logging in on the command line, through the [PAM jail](https://github.com/clipos-archive/src_platform_pam_jail) module, while on desktop environments, similar jailing is enforced by the graphical login interface.
User's data is stored on dedicated encrypted partitions.
There is one partition per user environment: the core system, the *low* level and the *high* level.
User partition devices are automatically open, decrypted and mounted (in their dedicated jail) when the user logs in.
The secret key used for the related cryptographic operations is derived from a password or decrypted by a smartcard.
Finally, the partition is unmounted and closed when the user session is closed.

A smartcard can be used simultaneously for user authentication and in multiple isolated environments at the same time thanks to [Caml Crush and multiple dedicated jails](https://github.com/clipos-archive/clipos4_portage-overlay-clip/blob/master/app-crypt/pkcs11-proxy/pkcs11-proxy-1.0.7-r3.ebuild#L86).
Smartcard management is handled through multiple packages: [ckiutl](https://github.com/clipos-archive/src_platform_ckiutl), [smartcard-monitor](https://github.com/clipos-archive/src_platform_smartcard-monitor), a [scdaemon](https://github.com/clipos-archive/src_platform_scdaemon)-like (PGP), etc.

Even if the system partition set can be encrypted and an early stage development for TPM support is present (e.g., [tpm-cmd](https://github.com/clipos-archive/src_platform_tpm-cmd), [clip-livecd](https://github.com/clipos-archive/src_platform_clip-livecd/blob/master/sbin-scripts/full_install.sh#L119), [clip-kernel](https://github.com/clipos-archive/clipos4_portage-overlay-clip/blob/master/sys-kernel/clip-kernel/files/initrd-clip#L473) and [syslinux-tpm-patches](https://github.com/clipos-archive/src_platform_syslinux-tpm-patches)), CLIP OS 4 does not include physical tampering in its threat model.
This is one of the main reasons for a 5th version of CLIP OS, not upgradable from the 4th one.

Multiple IPsec VPNs can be established by a client: *high* level network, update network, admin network and audit network.
A CLIP OS [gateway](https://github.com/clipos-archive/src_platform_clip-gtw-net) and a dedicated PKI can be set up to handle CLIP OS clients and their networks.

To avoid common entropy issues, a [kernel patch](https://github.com/clipos-archive/src_platform_clip-patches/blob/master/1702_get_random_bytes_rdrand.patch) and a [userspace daemon](https://github.com/clipos-archive/clipos4_portage-overlay/blob/master/sys-apps/timer_entropyd) feed the PRNG.

CLIP OS also provides user tools such as a simplified and hardened PKI management tool: [ANSSI-PKI](https://github.com/clipos-archive/src_platform_anssipki-cli).

# French documentation

The main public talk about CLIP OS 4 was given at the [SSTIC conference in 2015](https://www.sstic.org/2015/presentation/clip/).

This repository contains a selection of the initial documents in French targeting multiple audiences: end users, administrators and developers.

## User

* [Le changement de mot de passe dans CLIP](utilisateur/changer-mdp.pdf)
* [Écran étendu](utilisateur/configurer-ecran_etendu.pdf)
* [KRDC](utilisateur/configurer-krdc.pdf)
* [Échanger des documents entre les deux niveaux de CLIP](utilisateur/echanger-entre-clip-haut-et-clip-bas.pdf)
* [Guide de démarrage du client CLIP](utilisateur/tour-du-poste-clip.pdf)
* [Clés USB](utilisateur/utiliser-cles-usb.pdf)

## Administrator

* [Administration en ligne de commande d'une passerelle CLIP](administrateur/administration-ligne-de-commande-passerelle.pdf)
* [Mise en place de l'administration à distance des passerelles CLIP](administrateur/ajouter-acces_ssh.pdf)
* [Configuration DNS d'un poste CLIP](administrateur/configurer-dns.pdf)
* [Pare-feu](administrateur/configurer-firewall.pdf)
* [Fichier resolv.conf](administrateur/configurer-resolvconf.pdf)
* [Effacement manuel d'un poste bureautique CLIP](administrateur/effacer-manuellement-poste-bureautique-clip.pdf)
* [Guide d'utilisation d'une passerelle CLIP](administrateur/guide-utilisation-passerelle.pdf)
* [Installation de CLIP](administrateur/installer-passerelle_clip.pdf)
* [Rôle et gestion des certificats dans CLIP](administrateur/roles-certificats.pdf)

## Developer

* [Description Générale](developpeur/0001_Description_Generale_1.0.pdf)
* [Description Fonctionnelle](developpeur/1001a_Perimetre_Fonctionnel_CLIP-RM_1.0.4.pdf)
* [Architecture de sécurité](developpeur/1002_Architecture_Securite_1.2.pdf)
* [Paquetages CLIP](developpeur/1003_Paquetages_CLIP_1.1.pdf)
* [Support de l'UEFI](developpeur/1004_Support_de_l_UEFI_1.0.pdf)
* [Génération de paquetages](developpeur/1101_Generation_Paquetages_1.5.2.pdf)
* [Génération d'un support d'installation CLIP](developpeur/1102_Generation_CD_Installation_1.4.1.pdf)
* [Guide d'installation de l'environnement de développement](developpeur/1103_Environnement_de_Developpement_2.3.pdf)
* [CLIP-LSM](developpeur/1201_CLIP_LSM_2.2.pdf)
* [Patch VServer](developpeur/1202_Vserver_1.2.pdf)
* [PaX & grsecurity](developpeur/1203_PaX_Grsecurity_1.1.2.pdf)
* [Privilèges Linux](developpeur/1204_Privileges_Linux_1.0.1.pdf)
* [Générateur d'aléa noyau](developpeur/1206_Generateur_Alea_Noyau_1.0.pdf)
* [Séquences de démarrage et d'arrêt](developpeur/1301_Sequence_Demarrage_1.0.7.pdf)
* [Authentification locale](developpeur/1302_Authentification_CLIP_1.1.2.pdf)
* [X11 et cloisonnement graphique](developpeur/1303_X11_cloisonnement_graphique_1.1.3.pdf)
* [Cages et socle CLIP](developpeur/1304_Cages_CLIP_1.1.0.pdf)
* [Support des cartes à puce sous CLIP](developpeur/1305_Cartes_Puce_3.0.pdf)
* [TPM](developpeur/1307_TPM_0.0.pdf)
* [Cages RM](developpeur/1401_Cages_RM_1.2.pdf)
* [Configuration Réseau](developpeur/1501_Configuration_Reseau_2.6.pdf)
* [Installation CLIP](developpeur/2001_Installation_CLIP_1.1.0.pdf)
* [Guide de l'utilisateur CLIP-RM](developpeur/2101a_Guide_Utilisateur_CLIP-RM_1.4.pdf)
* [Guide de création de paquetage](developpeur/4001_Guide_de_Creation_de_Paquetage_1.3.pdf)

---

Copyright © 2018 [ANSSI](https://www.ssi.gouv.fr/).

CLIP OS is a trademark of the French Republic.
As a consequence, any use of the name "CLIP OS" has to be first authorized by the ANSSI.
This does not preclude changes to the software posted online and their republication or quotation from identifying the original software under the terms of the LGPL v2.1+ license.
Regardless, no use of the name "CLIP OS" on a modified version should suggest that this version is the original work published by the ANSSI.

The contents of this documentation is available under the Open License version 2.0 (compatible with the [CC-BY](https://creativecommons.org/licenses/by/2.0/) license) as published by [Etalab](https://www.etalab.gouv.fr/) (French task force for Open Data).
