# To create a new provider

1. create a new folder (ex: `do` for Cloudflare durable objects )

2. create the `memListProvider.ts` for small/medium lists to be loaded from the storage to mem

3. create the `sortedListProvider` for bigger lists (such a huge lists of blocked hosts/IPs)

4. update the `providerData.ts` as needed for setting the way in which the lists are created

5. update `data.ts` to return the list values