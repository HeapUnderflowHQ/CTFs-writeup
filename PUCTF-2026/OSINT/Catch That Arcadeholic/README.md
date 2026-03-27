%% 2026-03-12 23:29 %%
(NuttyShell CTF 2026)
(Write up by [Ezjfc](https://github.com/Ezjfc)).

```
Catch That Arcadeholic

One member of our CTF team went off to play music game arcade machines during PUCTF26 instead of staying to monitor the server.
He even sent a picture and make laugh to us!!! Bloody annoying!
Please help us to find his location base on his picture.
Wait? What do you mean he took a flight to leave???
==================================================
flag format: PUCTF26{[Arcade brand name]_[Building brand name]_[Name of the suburb where the picture was taken]_[Postcode where the picture was taken]_[Nearest Bus stop's stop ID]_[Nearest Supermarket from the arcade centre]_[MD5 hash value of the challenge title name]}
If there is space in the name, use "_" to replace
Example: "Hello World" --> "Hello_World"

Author: SleepyJeff
Flag Format: PUCTF26{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}}
```


# 1. Finding the Address

![[chall.jpg]]

Looking in the picture, we can see the word "Timezone" appearing on one of the machines at the right hand side. By looking up this word, we can know that **Timezone is an arcade franchiser** in Asia and Oceania. However, in 2026, there are 221 stores across these two continents. Therefore, we have to further narrow down the possible candidates. Fortunately, there is a website that could help us: https://zenius-i-vanisher.com/v5.2/arcades.php

This website included almost all arcade stores around the globe. Since maimai is an extremely and internationally popular game, we will instead put our focus on the game that is left to the maimai cabinets, which is Sound Voltex. By applying the filters Location: "Timezone"; Series: "SOUND VOLTEX"; we can see results are down to 4 and all of them are in Australia.

![[Pasted image 20260313020855.png]]

Nonetheless, we are still unsure of which store is the picture taken in since by the time of the CTF competition, all of the four stores appear to have upgraded their maimai to the very brand new version, which is "Circle", as denoted in the middle of each cabinet. This also means that looking up the store names on a search engine probably would not help as much as we expect most of them are outdated.
![[Pasted image 20260321032423.png]]

This forces us to observe the stores from other aspects and the best way to achieve this might be looking at their official websites:

- Timezone Garden City: https://www.timezonegames.com/en-au/venues/qld/timezone-garden-city/
- Timezone Haymarket: https://www.timezonegames.com/en-au/venues/nsw/timezone-haymarket/
- Timezone Central Park: https://www.timezonegames.com/en-au/venues/nsw/timezone-haymarket/
- Timezone Highpoint: https://www.timezonegames.com/en-au/venues/vic/timezone-highpoint/

After going through the websites one by one, we got a surprising discovery and that is the website of Timezone Garden City has whole 3D viewer that covered the entire store. Despite of the outdated store layout presented in the viewer, we are still be able to locate the approximate position where the picture was taken. Note that the searching in the GIF below is simplified, the actual process should take a while:
![[gardencity3d.gif]]

![[Pasted image 20260313030717.png]]

After all, we can finally conclude the picture is taken in Timezone Garden City, state of Queensland, Australia, with the address:
> Level 2 Westfield Garden City, Kessels Rd, Upper Mount Gravatt, QLD, 4122

To reveal the environment around the Timezone store, we type the address to a map service, such as Google Map. Looking in the map, it is notable that the shopping centre brand and suburb respectively should be **close to or related to "Westfield" and "Mt Gravatt"**
![[Pasted image 20260321035758.png]]



# 2. Supermarket and Bus Stop

After identifying the shopping centre, we can begin locating the closest supermarket and bus stop. Being easier, the first will be explained first: The following list shows the top common supermarkets in the state of Queensland:
- Woolworths
- Coles
- Aldi
- IGA (Metcash)

According to Google Map, **Woolworths appear to be the closest** one to the Timezone store among the three supermarkets presented in this Westfield.

Then, to locate the bus stop, we will need to leverage the Queensland Transit website or related third party websites, including [Translink](https://jp.translink.com.au/plan-your-journey/stops) and [AnyTrip](https://anytrip.com.au/). In this example, we will use the former website since Translink is the official public transport provider for the state of Queensland. In the website, we will enter "Garden city" and let the auto completion finish the rest. Now, a batch of bus stops pop up:
![[Pasted image 20260327203947.png]]
Being the **closest bus stop, 006515** should be what we have been looking for:
![[Pasted image 20260327204045.png]]

# 3. Forming the Flag

The only remaining item is the MD5 hash of the challenge title. This should be fairly easy to obtain with handled with care, such as not appending a line break character at the end of the title, which we learnt the hard way:
```
~
❯ echo "Catch That Arcadeholic" | openssl md5
MD5(stdin)= 4ae25ce0a55b6e7460a32473f00efa35

~
❯ echo -n "Catch That Arcadeholic" | openssl md5
MD5(stdin)= 06a4701552bbe840158857946dcb5853
```

At the end of the day, we end up with four potential flags to test out (due to the uncertainty of the suburb name):
- `PUCTF26{Timezone_Westfield_Mt_Gravatt_4122_006515_Woolworths_06a4701552bbe840158857946dcb5853}`
- `PUCTF26{Timezone_Westfield_Upper_Mt_Gravatt_4122_006515_Woolworths_06a4701552bbe840158857946dcb5853}`
- `PUCTF26{Timezone_Westfield_Mount_Gravatt_4122_006515_Woolworths_06a4701552bbe840158857946dcb5853}`
---
- `PUCTF26{Timezone_Westfield_Upper_Mount_Gravatt_4122_006515_Woolworths_06a4701552bbe840158857946dcb5853}`

Voilà, the last flag has successfully made our day.

%% 2026-03-27 20:49 %%

