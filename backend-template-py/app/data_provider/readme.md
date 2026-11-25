# To create a new provider

1. create a new folder (ex: `do` for Cloudflare durable objects )

2. create the `mem_list_provider.py` for small/medium lists to be loaded from the storage to mem

3. create the `sorted_list_provider.py` for bigger lists (such a huge lists of blocked hosts/IPs)

4. update the `provider_data.py` as needed for setting the way in which the lists are created

5. update `data.py` to return the list values
6. register the new backend in `provider.py` (`BACKENDS`)
