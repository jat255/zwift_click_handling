# Zwift Click Handler

This is a small python script that will translate clicks of the two buttons on a 
[Zwift Click](https://us.zwift.com/products/zwift-click-virtual-shifter?variant=43859765297408) into
plus/minus keystrokes to control virtual shifting on [indieVelo](https://indievelo.com/).

It makes heavy use of information reverse engineered and compiled by @ajchellew[^1] and @Makinolo[^2], so
credit for figuring out all the hard stuff should go to them. I just reproduced parts of that work in
Python (rather than the Android/C# examples in [^1]) so I could use it locally.

This code was developed on a Linux system, which uses BlueZ as the bluetooth backend. The version of BlueZ at the time of writing was 5.75-1. It will eventually be tested and deployed
on a Windows system. I have no idea if it will work on a Mac, but it might (I have no way to test).

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

In future iterations, these button presses will be translated into keyboard inputs (`+` / `-`) to control
the shifting in indieVelo.

## Running the code

1. Clone the repository, and make sure [poetry](https://python-poetry.org) is installed
2. From the code directory, run `poetry install --no-root`
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

[^1]: https://github.com/ajchellew/zwiftplay
[^2]: https://www.makinolo.com/blog/2023/10/08/connecting-to-zwift-play-controllers/
