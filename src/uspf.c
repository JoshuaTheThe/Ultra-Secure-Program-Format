
#include <uspf.h>
#include <sha256.h>

USPFImage USPFLoadImage(const char *const Path,
                        const char *const Password)
{
        if (Path == NULL || Password == NULL)
        {
                perror("Path or Password is NULL!\n");
                return (USPFImage){0};
        }

        FILE *fp = fopen(Path, "rb");
        if (!fp)
        {
                perror("fopen!\n");
                return (USPFImage){0};
        }

        USPFProgramHeader Phead = {0};
        size_t Read = fread(&Phead, 1, sizeof(Phead), fp);
        if (Read < sizeof(Phead))
        {
                return (USPFImage){0};
        }

        // TEST 00
        if (!(Phead.Magic[0] == 0x7f &&
             (Phead.Magic[1] == 'U' || Phead.Magic[1] == 'u') &&
             (Phead.Magic[2] == 'S' || Phead.Magic[2] == 's') &&
             (Phead.Magic[3] == 'P' || Phead.Magic[3] == 'p') &&
             (Phead.Magic[4] == 'F' || Phead.Magic[4] == 'f')))
        {
                perror("Illegal Magic!\n");
                return (USPFImage){0};
        }

        // TEST 01
        fclose(fp);
        return (USPFImage){0};
}
