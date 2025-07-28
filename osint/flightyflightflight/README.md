# Flightyflightflight [_snakeCTF 2023_]

**Category**: osint


## Challenge

Look mum I can fly!

## Attachments

A video of a plane taking off from an airport. 

## Solution

The first thing is to understand what the flag requires... i.e. the IATA and ICAO codes of the airport.

Second thing to do: check if there are metadata in the video (spoiler: no... too easy).

The easiest solution involves hypothesizing that the video was created by one of the organizing members of the CTF. Following this hypothesis, it was necessary to understand where the organizers of the CTF come from (i.e. Udine, north-east of Italy).

Once you understand this, you can use tools like FlightRadar24 to search for airports near a city. We can see how, at reasonable distances from Udine, there are various airports: Trieste Friuli Venezia Giulia Airport, Ljubljana Joze Pucnik Airport, Venice Treviso Airport and Venice Marco Polo Airport.

Once the nearby airports had been identified, it was sufficient to compare their appearance with that of the airport shown in the video, discovering that it was Venice Marco Polo Airport. After identifying the airport, it was sufficient to search for the IATA and ICAO codes of the identified airport.

Obviously, there are other solutions such as the use of GeoINT tools (such as Google Image Search), or the use of Flight Connections to identify the airports from which certain airlines present in some moments of the video fly, filtering the possible solutions.


> snakeCTF{VCE_LIPZ}


