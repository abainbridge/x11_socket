# x11_socket
Minimal example of directly talking to the X Server instead of using a library like xlib or xcb.

Someone on Stackoverflow asked how to talk directly to the X server. Here's the accepted answer saying that it is basically impossible. https://stackoverflow.com/a/12112055/66088. So I proudly present a few hundred lines of trivial C code that does the impossible. I encourage you to compare the complexity of this code with JUST THE BUILD INSTRUCTIONS for the library everyone recommends you use: https://xcb.freedesktop.org/DevelopersGuide/

Admittedly, this approach presented here is best suited to applications/libraries that only need the bare minimum of X11 features. And the code here assumes your system uses .Xauthority files with MIT magic cookies. And that you only have one display. And that your username is "andy". But these are small obstacles compared to trying to build xcb.

## Useful stuff
Documentation of the X11 protocol - https://www.x.org/releases/X11R7.7/doc/xproto/x11protocol.html

The default way apps talk to the X server is via a Unix inter-process communication socket. To trace the traffic on that interface, you can do the following:

    sudo strace -qqxxttts9999999 -e writev,recvmsg,recvfrom -o xlog <your app> 
    cat xlog | perl -lne '
        if (($t,$f,$p) = /^([\d.]+) (writev|recvmsg|recvfrom)\(3, (.*)/) {
          @p = ($p =~ /\\x(..)/g);
          $dir = $f eq "writev" ? "O" : "I";
          while (@p) {print "$dir $t 0000 " . join(" ", splice @p,0,64000)}
        }' | text2pcap -T6000,1234 -Dqt %s. - - | wireshark -ki -

Credit to Stéphane Chazelas's Stack Exchange answer for these magic runes: https://unix.stackexchange.com/a/192011/30790
