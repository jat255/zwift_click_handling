# Zwift Click Handler

This is a small python script that will translate clicks of the two buttons on a 
[Zwift Click](https://us.zwift.com/products/zwift-click-virtual-shifter?variant=43859765297408) into
plus/minus keystrokes to control virtual shifting on [indieVelo](https://indievelo.com/).

It makes heavy use of information reverse engineered and compiled by @ajchellew[^1] and @Makinolo[^2], so
credit for figuring out all the hard stuff should go to them. I just reproduced parts of that work in
Python (rather than the Android/C# examples in [^1]) so I could use it locally.

This code was developed on a Linux system, which uses BlueZ as the bluetooth backend. The version of BlueZ at the time of writing was 5.75-1. It has been tested and I use it on a Window 10 Pro system with an Intel Bluetooth adapter. I have no idea if it will work on a Mac, but it might (I have no way to test).

In it's current implementation, it will connect to a Zwift Click (without encryption, I couldn't get that
part working) and print out to the console when a button press/release is detected, as well as when
the Click broadcasts its current battery level. Here's an example of the
output from pressing and releasing the plus button and then the minus button three times each:

```
[11:49:54] INFO     Set up logging @ "2024-05-13T11:49:54.795359-06:00"                  app.py:40
           INFO     Setting up BLE client **WITHOUT** encryption                         app.py:49
           INFO     Using MAC of "None"                                                  app.py:51
           INFO     Scanning for Click...                                                app.py:89
[11:49:55] INFO     Found Click device with MAC "DE:53:77:EB:6B:A1"                      app.py:93
           INFO     Waiting for device to be visible; please press a button on the       app.py:235
                    Click if it is not already in "connecting" mode (pulsing blue light)
[11:49:58] INFO     Click device found; Starting connection handshake                    app.py:246
           INFO     Finished handshake; waiting for input (press `Ctrl-C` to exit)       app.py:257
[11:49:59] INFO     Plus button PRESSED                                                  app.py:146
           INFO     Current battery level is 93                                          app.py:120
[11:50:00] INFO     Plus button RELEASED                                                 app.py:146
           INFO     Plus button PRESSED                                                  app.py:146
           INFO     Plus button RELEASED                                                 app.py:146
[11:50:01] INFO     Plus button PRESSED                                                  app.py:146
           INFO     Plus button RELEASED                                                 app.py:146
[11:50:02] INFO     Minus button PRESSED                                                 app.py:148
           INFO     Minus button RELEASED                                                app.py:148
           INFO     Current battery level is 93                                          app.py:120
           INFO     Minus button PRESSED                                                 app.py:148
           INFO     Minus button RELEASED                                                app.py:148
           INFO     Minus button PRESSED                                                 app.py:148
           INFO     Minus button RELEASED                                                app.py:148
```

These button presses are then translated into keyboard inputs (`+` / `-`), which will control virtual 
shifting in indieVelo if the application has focus.

**NB:** Because of limitations on the [`keyboard`](https://github.com/boppreh/keyboard/blob/master/keyboard/__init__.py#L90) library,
if you want to send the plus/minus commands on Linux, you need to run this script as `root`. All caveats
around that apply, namely, you should probably look at the code to make sure it's not doing something naughty
before running random scripts as `root`.

## Running the code

1. Clone the repository, and make sure [poetry](https://python-poetry.org) is installed
2. From the code directory, run `poetry install --no-root`
   - Note, when installing on Windows, it may be required to enable long paths (it was for me). To do this, open `regedit` and set `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled` to `1`
   - When running on Windows, I still ran into path length issues due to poetry putting files in some deep `AppData` folder. The simplest solution appeared to be to install the poetry virtualenv in the folder by setting `poetry config virtualenvs.in-project true` before running the `install` command
3. Press a button on your Click to put it in "connecting" mode (the LED should pulse blue). It will stay in 
   "connecting" mode for about a minute, after which, you'll need to press a button again to wake it up.
4. Run the code via `poetry run python app.py`. If all works correctly, it should give you an output something like above, and
   if you start pressing the buttons on the Click, you should see output in the terminal indicating that they were registered
   - If you're curious, supplying the `-v` will increase the log verbosity
   - You can provide a specific MAC address to use (if you have multiple Clicks around, this could be useful) in one of two ways:
     1. Supply the MAC address as a string on the command line, e.g. `poetry run python app.py "DE:53:77:EB:6B:A1"`
     2. Supply thte MAC address as an environment variable named    
        `CLICK_MAC_ADDRESS`. This can be done by uncommenting and 
        changing the value in the `.env` file, or at runtime via 
        something like `CLICK_MAC_ADDRESS="DE:53:77:EB:6B:A1" poetry run python app.py`
5. Press `Ctrl-C` to exit

- There's also a file provided named `run.bat` that will run the script. I created a shortcut to that on my desktop,
  and I run that to connect the Click before I start up indieVelo, and it all seems to work as expected

### Demo video

https://github.com/jat255/zwift_click_handling/assets/1278301/f5349b74-b5bb-481e-b7fc-d72df7a23dc8

## Disclaimers

### Trademarks

"Zwift", "Zwift Click", and any related terms are registered (or unregistered) trademarks of [Zwift Inc.](https://zwift.com). The use of these marks is purely descriptive in manner and not intended to imply any endorsement of the code provided in this repository by the marks' owners.

"indieVelo" and any related terms are registered (or unregistered) trademarks of [indieVelo](https://indievelo.com/about/). The use of this mark is pureley descriptive in manner and not intended to imply any endorsement of the code provided in this repository by the mark's owners.

### Code

There are inherent dangers in the use of any software available for download on the Internet, and we caution you to make sure that you completely understand the potential risks before downloading any of the software.

The Software and code samples available on this website are provided "as is" without warranty of any kind, either express or implied. Use at your own risk.

The use of the software and scripts downloaded on this site is done at your own discretion and risk and with agreement that you will be solely responsible for any damage to your computer system or loss of data that results from such activities. You are solely responsible for adequate protection and backup of the data and equipment used in connection with any of the software, and we will not be liable for any damages that you may suffer in connection with using, modifying or distributing any of this software. No advice or information, whether oral or written, obtained by you from us or from this website shall create any warranty for the software.

We make makes no warranty that

- the software will meet your requirements
- the software will be uninterrupted, timely, secure or error-free
- the results that may be obtained from the use of the software will be effective, accurate or reliable
- the quality of the software will meet your expectations
- any errors in the software obtained from us will be corrected.

The software, code sample and their documentation made available in this repository:

- could include technical or other mistakes, inaccuracies or typographical errors. We may make changes to the software or documentation made available on its web site at any time without prior-notice.
- may be out of date, and we make no commitment to update such materials.

We assume no responsibility for errors or omissions in the software or documentation available from its web site.

In no event shall we be liable to you or any third parties for any special, punitive, incidental, indirect or consequential damages of any kind, or any damages whatsoever, including, without limitation, those resulting from loss of use, data or profits, and on any theory of liability, arising out of or in connection with the use of this software.

## Footnotes

[^1]: https://github.com/ajchellew/zwiftplay
[^2]: https://www.makinolo.com/blog/2023/10/08/connecting-to-zwift-play-controllers/
