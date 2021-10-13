This project is still very much a work in progress and is not intended to be used yet.

---

# Pwnts

A Red Team tool for scoring during a cybersecurity competition.

**Pwnts** is an HTTPS web application consisting of a publicly-accessible (by the regular competitors) scoreboard and a private, Red Teams-only [Golang](https://golang.org/) binary Agent generator.

## Premise

Pwnts accounts are created and disseminated to each Red Team before the competition begins. Through the web application, authenticated Red Teamers are able to generate Golang binary Agents to run on their pwnd targets by providing values for a handful of parameters.

More *pwnts* are awarded for faster callback rates with a maximum of 100 pwnts awarded for an Agent calling back every minute. The minimum rate is 5 pwnts every three hours. In between, pwnts are awarded on an exponential scale.

Double pwnts are awarded for an Agent with `root` access compared to an Agent with standard privileges. Level of access is determined at the server by examining the source port. If the Agent has called back from a privileged port (<1024), double pwnts will be given, increasing the maximum pwnts per callback to 200.

## Web App vs Callback Server

Pwnts is designed such that the web application and callback server can run on different ports. This design is subject to change, possibly by integrating the callback server directly into the web application.

Although in either scenario both applications will be running on a singular host, I'd hoped to make Pwnts as modular as possible to make Agent detection more difficult in the future. Since the non-Red Team competitors will be able to see the public scoreboard, it would be wise of them to analyze outbound traffic to the scoreboard's IP address. This is what I would like to obfuscate.
