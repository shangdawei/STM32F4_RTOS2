#include "BSP.h"

#define GPIOD_BASE_ADDR           ((unsigned int)0x40020C00)

#define GPIOD_MODER               (*(volatile unsigned int*)(GPIOD_BASE_ADDR + 0x00))
#define GPIOD_ODR                 (*(volatile unsigned int*)(GPIOD_BASE_ADDR + 0x14))
#define GPIOD_BSRR                (*(volatile unsigned int*)(GPIOD_BASE_ADDR + 0x18))

#define RCC_BASE_ADDR             ((unsigned int)(0x40023800))
#define RCC_AHB1RSTR              (*(volatile unsigned int*)(RCC_BASE_ADDR + 0x10))
#define RCC_AHBENR                (*(volatile unsigned int*)(RCC_BASE_ADDR + 0x30))

#define RCC_LEDPORT_RSTR          RCC_AHB1RSTR
#define RCC_LEDPORT_ENR           RCC_AHBENR
#define RCC_LEDPORT_BIT           (3)

#define LED_PORT_MODER            GPIOD_MODER
#define LED_PORT_ODR              GPIOD_ODR
#define LED_PORT_BSRR             GPIOD_BSRR

#define LED0_BIT                  (12)
#define LED1_BIT                  (14)
#define LED_MASK_ALL              ((1uL << LED0_BIT) | (1uL << LED1_BIT))

void BSP_InitLED( void )
{
  RCC_LEDPORT_ENR &= ~( 1uL << RCC_LEDPORT_BIT );
  RCC_LEDPORT_RSTR &= ~( 1uL << RCC_LEDPORT_BIT );
  RCC_LEDPORT_ENR |= ( 1uL << RCC_LEDPORT_BIT );

  LED_PORT_MODER &= ~( 3uL << ( LED0_BIT * 2 )) | ( 3uL << ( LED1_BIT * 2 ));
  LED_PORT_MODER |= ( 1uL << ( LED0_BIT * 2 )) | ( 1uL << ( LED1_BIT * 2 ));
  LED_PORT_BSRR = ( 0x10000uL << LED0_BIT ) | ( 0x10000uL << LED1_BIT );
}

void BSP_SetLED( int Index )
{
  if ( Index == 0 )
  {
    LED_PORT_BSRR = ( 1uL << LED0_BIT );
  }
  else if ( Index == 1 )
  {
    LED_PORT_BSRR = ( 1uL << LED1_BIT );
  }
}

void BSP_ClrLED( int Index )
{
  if ( Index == 0 )
  {
    LED_PORT_BSRR = ( 0x10000uL << LED0_BIT );
  }
  else if ( Index == 1 )
  {
    LED_PORT_BSRR = ( 0x10000uL << LED1_BIT );
  }
}

void BSP_ToggleLED( int Index )
{
  if ( Index == 0 )
  {
    if (( LED_PORT_ODR &( 1uL << LED0_BIT )) == 0 )
    {
      LED_PORT_BSRR = ( 1uL << LED0_BIT );
    }
    else
    {
      LED_PORT_BSRR = ( 0x10000uL << LED0_BIT );
    }
  }
  else if ( Index == 1 )
  {
    if (( LED_PORT_ODR &( 1uL << LED1_BIT )) == 0 )
    {
      LED_PORT_BSRR = ( 1uL << LED1_BIT );
    }
    else
    {
      LED_PORT_BSRR = ( 0x10000uL << LED1_BIT );
    }
  }
}