![GitHub last commit](https://img.shields.io/github/last-commit/s-christian/pwnts?style=flat&logo=github)
![Lines of code](https://img.shields.io/tokei/lines/github/s-christian/pwnts?style=flat&logo=github)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/s-christian/pwnts?style=flat&logo=github)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/s-christian/pwnts?style=flat&logo=go)

🎅 **It works!**

Everything should be fully functional at this point including agent generation through the authenticated dashboard and dynamic scoreboard updates.

More testing is needed across various operating systems, and patches may come in to address unforseen issues. Otherwise, feel free to try this out and let me know what you think.

---

🎃 **Halloween update!**

👻 *Theoretically*, this might be usable if you manually generate your Agents. The server should be complete, and the site's scoreboard for displaying teams' current scores should be working.

I have not yet tested deploying multiple agents across multiple targets, but will soon. My immediate to-do is to get authenticated Agent generation working on the site.

---

# Pwnts

![Website Preview](images/website_preview.png)

A Red Team tool for scoring during exercises and competitions.

**Pwnts** is both an Agent callback server and a web application consisting of a publicly-accessible scoreboard and a private, Red Teams-only [Golang](https://golang.org/) binary Agent generator.

Compiled Go binaries have ***zero dependencies***, and the web application likewise relies on no external resources. Everything is designed to be baked-in and ready to go.

## Running

There are currently no pre-compiled binaries, though I will provide them shortly.

Follow these steps to get everything set up and running:

1. Initialize the database: `go run tools/databaseTools.go --init-db`
2. Add your targets (IPs) with point values to `./tools/targets.txt`. Follow the format of the examples already in the file.
3. Register targets: `go run tools/databaseTools.go --register-targets /tools/targets.txt`
4. Create teams: `go run tools/databaseTools.go --register-team --team-name <name> --team-password <password>`
5. Start the site: `go run site/site.go`
6. Start the callback server: `go run server/server.go`
7. Log in to the site, generate an agent, then execute it on your pwned host.

---

## Premise

Pwnts accounts are created and disseminated to each Red Team before the competition begins. Through the web application, authenticated Red Teamers are able to generate Golang binary Agents to run on their pwnd targets by providing values for a handful of parameters.

In-scope targets are registered with their value which is then multiplied by an adjustable expoential decay factor. This factor is determined by callback frequency where more frequent callbacks means more ***pwnts***.

***Pwnts*** (points) are kept track of as a current total, not a cumulative sum. If a defender removes your agent from their system, you will lose pwnts! However, all Agent checkins are kept track of so that a sum can be calculated if you wish.

## Web App vs Callback Server

Pwnts is designed such that the web application and callback server can run on different ports. This design is subject to change, possibly by integrating the callback server directly into the web application.

Although in either scenario both applications will be running on a singular host, I'd hoped to make Pwnts as modular as possible to make Agent detection more difficult in the future. Since the defenders will be able to see the public scoreboard, it would be wise of them to analyze outbound traffic to the scoreboard's IP address. This is what I would like to separate in the future by most likely changing the backend database to a full SQL engine like MySQL and hosting it on another server.