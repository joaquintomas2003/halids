# HALIDS en Netronome Agilio

## Estructura
- `src/`: Contiene todo el código fuente del proyecto.
  - `src/bin/`: Scripts para automatizar distintos procesos.
  - `src/oracle.py`: Código del Oracle en Python.
  - `src/main.p4`: Archivo principal del programa en P4.
  - `src/ml_data/`: Archivos necesarios para el funcionamiento del Oracle.
## Como usar?
Estando en `src/`

1. Copiar `datos_limpios.csv` a `ml/data`. El archivo `datos_limpios.csv` puede encontrarse [acá](https://gitlab.fing.edu.uy/bbrandino/halids/-/blob/6fc316033996627894d005f8b995d956c5c62bf0/software/1tree/datos_limpios.csv).

2. Build
```
bin/p4 buildc main.p4
```

3. Cargar en la placa
```
bin/p4 design-load
```

4. Iniciar Oracle
```
sudo python3 oracle.py
```

5. Una vez el oracle esté listo para recibir paquetes se puede empezar a enviar paquetes a la interfaz `vf0_1`
```
sudo tcpreplay -i vf0_1 <ARCHIVO_PCAP>
```
- El archivo `.pcap` utilizado para nuestras pruebas se puede encontrar [acá](https://gitlab.fing.edu.uy/bbrandino/halids/-/blob/6fc316033996627894d005f8b995d956c5c62bf0/software/large_cap.pcap).
- Para setear cantidad máxima de paquetes de `tcpreplay` usar flag `--limit=<CANTIDAD>`. 
- Para controlar el throttle de `tcprplay` usar flag `--pps=<CANTIDAD_DE_PKTS_POR_SEG>`
