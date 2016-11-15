#ifndef BSP_H
#define BSP_H

#ifdef __cplusplus
extern "C"
{
#endif

void BSP_InitLED( void );
void BSP_SetLED( int Index );
void BSP_ClrLED( int Index );
void BSP_ToggleLED( int Index );

#ifdef __cplusplus
}
#endif

#endif