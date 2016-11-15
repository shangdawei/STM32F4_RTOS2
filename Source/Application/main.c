#include "stm32f4xx.h"
#include "cmsis_os2.h"
#include "BSP.h"

void HPTask( void * Arg )
{
  while ( 1 )
  {
    BSP_ToggleLED( 0 );
    osDelay( 50 );
  }
}

void LPTask( void * Arg )
{
  while ( 1 )
  {
    BSP_ToggleLED( 1 );
    osDelay( 200 );
  }
}


int main( void )
{
  SystemCoreClockUpdate();

  BSP_InitLED();

  osKernelInitialize();

  osThreadNew( LPTask, NULL, NULL );
  osThreadNew( HPTask, NULL, NULL );

  if ( osKernelGetState() == osKernelReady )
    osKernelStart();

  while ( 1 )
  {
  }
}