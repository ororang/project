#include <stdio.h>

int main(){
    
    int choice;

    while (1)
    {
        printf("1. 가짜 AP 생성 2. 종료\n");
        scanf("%d",&choice);
        if( choice ==  1){
            printf("가짜 AP 생성");
            system("sudo ./start_evil_twin.sh");
            break;
        }else if( choice == 2){
            printf("프로그램 종료");
            break;
        }
    }
}
