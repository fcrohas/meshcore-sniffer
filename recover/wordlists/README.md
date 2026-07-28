# Bundled wordlists

## french.txt

Source: [Taknok/French-Wordlist](https://github.com/Taknok/French-Wordlist)
(`francais.txt`), MIT licensed -- see `French-Wordlist-LICENSE` in this
directory for the full license text and copyright notice, vendored
here per the MIT license's attribution requirement.

~22.7k common French words. Used as the default candidate list for
MeshCore hashtag-channel dictionary attacks (`meshcore_hashtag_dict.c`'s
background attack in the main sniffer, and the offline
`meshcore-recover` tool) -- a hashtag channel's secret is derived from
a human-typed name (`meshcore_channel_hashtag_secret()`), and French
community channel names are drawn from ordinary vocabulary plus
`fr-<department/region>` codes (see `builtin_candidates()` in
`../meshcore-recover.c` for those).

To refresh from upstream:

```bash
curl -sL https://raw.githubusercontent.com/Taknok/French-Wordlist/master/francais.txt \
  -o recover/wordlists/french.txt
curl -sL https://raw.githubusercontent.com/Taknok/French-Wordlist/master/LICENSE \
  -o recover/wordlists/French-Wordlist-LICENSE
```
