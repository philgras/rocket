#include<iostream>
#include<string>


int main(int nargs, char** vargs){

    for(int i = 0; i < nargs; ++i){
        std::cout<<vargs[i]<<std::endl;
    }
}
