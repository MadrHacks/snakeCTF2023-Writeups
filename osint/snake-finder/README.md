# Snake Finder [_snakeCTF 2023_]

**Category**: osint


## Challenge

In a place where people always exaggerate their ability, In a digital jungle where serpents reside, Twisting and turning, their secrets they hide. With venomous fangs and coils that entwine, A path through the bytes, a treasure you'll find.

Seek knowledge in bites, bytes, and more, Where data slithers on the cyber shore. Hack through the brush, with caution take heed, To reveal the past, where secrets were freed.

This puzzle to solve, a riddle, a quest, Navigate the twists, put your skills to the test. To the serpent's lair, you must now aspire, In the world of the web, where the past does transpire.

Unravel the code, the serpent's embrace, In the virtual realm, find your rightful place. When you're ready to claim the treasure's grand prize, You'll find it in history, where the past never dies.

## Solution

The challenge description is a poem, so we have to find the correct interpretation of it.

Here is my interpretation:
- It is mentioned a "digital jungle where serpents reside", so we can think of the Internet.
- The poem also mentions "bytes", so we can think of the Internet as a digital jungle where data slithers on the cyber shore.
- The poem also mentions "history", so we can think of the Internet as a place where the past does transpire.
- The poem says that to solve, we have to "navigate the twists", so we can think of the Internet as a place where we have to navigate through links.
- Our target is a place where "people always exaggerate their ability", so we can think of social media.
- We'll find the flag in the "history" of a social media profile, where "history" could mean the feed or a wayback machine.

We can now search for a social media profile that fits the description.

We can find the official website of MadrHacks on Google, and we can find their social media profiles on the website.

We can find both their Instagram and LinkedIn profiles.

We can try to check both feeds, but we can't find the flag.

Could that "history" mean the literal history of the profile?

We can try to use the Wayback Machine to find the flag.

We search for the LinkedIn profile on the Wayback Machine, and we can find the flag.

> snakeCTF{now-we-are-linked-in-haha-you-get-it?}

