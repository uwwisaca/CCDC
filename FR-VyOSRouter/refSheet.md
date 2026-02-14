# VyOS Reference Sheet

Reference the official documentation if needed: https://docs.vyos.io/en/latest/cli.html

Reference the quick-start documentation here: https://docs.vyos.io/en/1.4/quick-start.html

**VyOS supports smart command completion; if stuck, attempt to use tab completion in order to resolve the situation.**

When viewing in page mode (Operational Mode; show command, etc.) the following commands are available:

`q` key can be used to cancel output

`space` will scroll down one page

`b` will scroll back one page

`return` will scroll down one line

`up-arrow` and `down-arrow` will scroll up or down one line at a time respectively

`left-arrow` and `right-arrow` can be used to scroll left or right in the event that the output has lines which exceed the terminal size.

You can also interactively scroll through the terminal window using `Shift + PageUp` or `Shift + PageDown` when scrolling is unavailable.

## Changing the Default Password & Disabling SSH

Run the following commands when the drop flag is received. The plaintext-password is encrypted when you commit it.

    configure
    set system login user vyos authentication plaintext-password <Password>
    delete service ssh
    commit
    save
    exit

## Basic Hardening

Create another user that replaces the vyos user. Enable OTP for the created user. Disable ssh. Disable the vyos user.

    configure
    set system login user <username> authentication plaintext-password <password>
    generate system login username <username> otp-key hotp-time rate-limit 3 rate-time 30 window-size 3
    set system login user vyos disable
    curl -fsSL https://raw.githubusercontent.com/uwwisaca/CCDC/refs/heads/main/FR-VyOSRouter/vyosfw.sh -o /tmp/vyosfw.sh
    source /tmp/vyosfw.sh
    commit-confirm 5
    save
    exit
    confirm

## Operational Mode Basics

For basically any command that can be run within configuration mode ("set" commands), you can use show to display the current state of the console at that path.

### Show OS Version, Commit Pin, and Architecture

    show version

### Show Running Configuration

    show config
OR

    show configuration

### Show Configuration Commands: Show Commands Required to Make Current Configuration

    show configuration commands

## Configuration Mode Basics

All commands executed here are relative to the configuration level you have entered. You can do everything from the top level, but commands will be quite lengthy when manually typing them.

The current hierarchy level can be changed by the "edit" command.

For example, instead of writing "set interfaces ethernet eth0 address dhcp", you are able to use "edit interfaces ethernet eth0" and then run "set address dhcp" or any other necessary command on that interface as if you had already filled in the rest of the command.

### Enter Configuration Mode

    configure

### Commit States

All changes made in configuration mode must be committed to the server, or they will not be applied.

    commit

Changes may also require confirmation from an admin after application. For example, if you change the internal interface and it may bring down network access, enter:

    commit-confirm <minutes>

This will require that you type "confirm" into the console before the timer reaches zero, else the server will revert the changes.

You can view a commit history using:

    show system commit

You can compare commits (similar to git diff) using [where N and M are revision numbers]:

    compare <saved | N> <M>

You can also compare the active configuration to a revision using:

    show system commit diff <N>

You can roll back to a configuration state using (Reboot Required!):

    rollback <N>

You can load a configuration state using:

    load <URI>

### Save Changes

After committing changes, they must be saved to the server or they will not survive a reboot.

    save

### Exit or Discard Changes

If you want to exit configuration mode, simply enter:

    exit
However, if you have unsaved changes, enter:

    exit discard

## Interfaces (Config Mode)

VyOS and CCDC primarily use Ethernet type interfaces for connections.

### Set Enabled/Disabled State

Set if the interface is up or down. Disabled state = Administratively Down.

    set interfaces ethernet <interface> enable
    set interfaces ethernet <interface> disable

### Set IP

Address must be entered with CIDR Notation.

    set interfaces ethernet <interface> address <address | dhcp>

## Routes (Config Mode)

The CCDC invitationals environment uses static routes for routing. This is useful as it is by far the simplest routing protocol that VyOS supports.

### Static Unicast Routes (MOST COMMON):

    set protocols static route <subnet> next-hop <address>

### Static Interface Routes

    set protocols static route <subnet> interface <interface>

### Static Reject Routes

    set protocol static route <subnet> reject

### Static Blackhole Routes (Silent Discard)

    set protocols static route <subnet> blackhole

## DNS (Config Mode)

## NTP (Config Mode)

## NAT Translation