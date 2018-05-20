# ncd
**ncd** is my personal script-based network configuration daemon.

## Why?
### Short answer:
I just wanted to roll my own program to see how small I could get it to be.

### Long answer:
I happen to be the owner of an old laptop that tends to get carried around quite often, 
so I wanted a program to autoconfigure my network settings on a network-to-network
basis (Using one config for my local wifi network, another for some other network,
so on and so forth, along with a fallback for any unknown network).

Why write a program when such a thing could be achieved easily by achieved by using GNOME's
Network Manager, for example? Mostly because I was trying to see how minimal I could get an
install that suited me to be, so I didn't really want to pull lots of dependencies to use *X*
or *Y*, but also because I wanted to
take that as an opportunity to learn more stuff and to exercise a bit.

So I wrote my own.

## How does it work?
Firstly, the user must provide the program with the scripts to be run inside a directory that
will be reffered to from now on as "the catalogue", whose location is stored in `ncd_settings.catalogue` 
(which for now can only be changed by changing `ncd_settings_load_defaults()`, and defaults to 
`/var/netconfd/scripts`), in the following structure:
```
- <catalogue>
| - <interface name>
| | - <script name>
| | | - run
| | | - stop
| | ...
| | - <script name>
| | | - run
| | | - stop
```
So a valid one might look like:
```
- /var/netconfd/
| - wlan0/
| | - 00-beernpretzels
| | | - run
| | | - stop
| | ...
| | - 10-notavirus
| | | - run
| | | - stop
```

`<TODO>`
