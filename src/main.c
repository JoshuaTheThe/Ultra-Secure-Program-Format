#include <uspf.h>

int main(void)
{
        USPFImage Image = {0};
        Image = USPFLoadImage("test/example.sp", "a");
        return 0;
}
