## Prueba 1
| Counter | Value  |
|--|--|
| Total Packets | 30206 |
| TCP or UDP packets | 28900 |
| CheckFeature() | 83976 |
| SetClass() | 0 |
| Class == SEND_TO_ORACLE | 0 |
| Class == 0 | 0 |
| Class == 1 | 0 |
| Class Not Assigned | 28900 |

Lo primero que se observa es que la clase no se esta seteando. Nunca se llama al SetClass(), y como consecuencia  la `class` siempre termina `Not Assigned`.

Lo segundo que observamos es que el count de la action CheckFeature() es arpoximademente el triple de la cantidad de paquetes TCP o UDP, es decir, de los paquetes elegibles para ser procesados por HALIDS.
28900 * 3 = 86.700 ~ 83976

Lo esperable sería que el count de CheckFeature() sea mayor, entre 4 y 5 veces la cantidad de paquetes procesados por HALIDS, pues la clase se setea recién en los niveles 4 y 5, y hasta que la clase no esta seteada se debería seguir llamando a CheckFeature.

Este número bajo de llamadas a CheckFeature() junto con el hecho de que nunca se llega a llamar a SetClass() parecería indicar que los paquetes no están atravesando todos los niveles.

¿Que está sucediendo?

## Prueba 2
Para poder ver con mas claridad en que casos se está ejecutando `CheckFeature()`, agregamos un bit de control `meta.checked_feature` que seteamos en 1 cada vez que se ejecuta dicha action.

```
  350   action CheckFeature(bit<16> node_id, bit<16> f_inout, bit<32> threshold) {
  351     bit<32> feature = 0;
  352     bit<32> th = threshold;
  353     bit<16> f = f_inout + 1;
~ 354     counter_.count(2);
+ 355     meta.checked_feature = 1;
  356
  357     if (f==1){ ...
```
Incialicemos el bit en 0 y pongamos counters luego del apply de cada nivel viendo si efectivamente ese bit se seteó.
```
+ 693           meta.checked_feature = 0;
  694           level1.apply();
+ 695           if (meta.checked_feature == 1){
+ 696             counter_.count(8);
+ 697             meta.checked_feature = 0;
+ 698           }
  699           if (meta.class == CLASS_NOT_SET) {
  700             level2.apply();
+ 701             if (meta.checked_feature == 1){
+ 702               counter_.count(9);
+ 703               meta.checked_feature = 0;
+ 704             }
  705             if (meta.class == CLASS_NOT_SET) {
  706               level3.apply();
+ 707               if (meta.checked_feature == 1){
+ 708                 counter_.count(10);
+ 709                 meta.checked_feature = 0;
+ 710               }
  711               if (meta.class == CLASS_NOT_SET) {
  712                 level4.apply();
+ 713                 if (meta.checked_feature == 1){
+ 714                   counter_.count(11);
+ 715                   meta.checked_feature = 0;
+ 716                 }
  717                 if (meta.class == CLASS_NOT_SET) {
  718                   level5.apply();
+ 719                   if (meta.checked_feature == 1){
+ 720                     counter_.count(12);
+ 721                     meta.checked_feature = 0;
+ 722                   }
  723                 }
  724               }
  725             }
  726           }
  ```

| Counter | Value  |
|--|--|
| Total Packets | 30108 |
| TCP or UDP packets | 28900 |
| CheckFeature() | 82118 |
| SetClass() | 0 |
| Class == SEND_TO_ORACLE | 0 |
| Class == 0 | 0 |
| Class == 1 | 0 |
| Class Not Assigned | 27042 |
| Luego de level1.apply() | 27992 |
| Luego de level2.apply() | 27992 |
| Luego de level3.apply() | 26134 |
| Luego de level4.apply() | 0 |
| luego de level5.apply() | 0 |

## Prueba 3
Simplifiquemos el árbol lo más posible. 
Tenemos solamente la siguiente rama en la reglas:
```
  1 /opt/netronome/p4/bin/rtecli tables add --table-name ingress::level1 --rule rule1_level1 --match '{"ingress::scalars.metadata@node_id": {"value": "0"}, "ingress::scalars.metadata@isTrue": {"value": "1"}, "ing    ress::scalars.metadata@prevFeature": {"value": "0"}}' --action '{"type": "ingress::CheckFeature", "data": {"threshold": {"value": "24125"}, "node_id": {"value": "1"}, "f_inout": {"value": "9"}}}'
  2 /opt/netronome/p4/bin/rtecli tables add --table-name ingress::level2 --rule rule2_level2 --match '{"ingress::scalars.metadata@node_id": {"value": "1"}, "ingress::scalars.metadata@isTrue": {"value": "1"}, "ing    ress::scalars.metadata@prevFeature": {"value": "9"}}' --action '{"type": "ingress::CheckFeature", "data": {"threshold": {"value": "0"}, "node_id": {"value": "2"}, "f_inout": {"value": "4"}}}'
  3 /opt/netronome/p4/bin/rtecli tables add --table-name ingress::level3 --rule rule3_level3 --match '{"ingress::scalars.metadata@node_id": {"value": "2"}, "ingress::scalars.metadata@isTrue": {"value": "1"}, "ing    ress::scalars.metadata@prevFeature": {"value": "4"}}' --action '{"type": "ingress::CheckFeature", "data": {"threshold": {"value": "1"}, "node_id": {"value": "3"}, "f_inout": {"value": "1"}}}'
  4 /opt/netronome/p4/bin/rtecli tables add --table-name ingress::level4 --rule rule4_level4 --match '{"ingress::scalars.metadata@node_id": {"value": "3"}, "ingress::scalars.metadata@isTrue": {"value": "1"}, "ing    ress::scalars.metadata@prevFeature": {"value": "1"}}' --action '{"type": "ingress::CheckFeature", "data": {"threshold": {"value": "61"}, "node_id": {"value": "4"}, "f_inout": {"value": "10"}}}'
  5 /opt/netronome/p4/bin/rtecli tables add --table-name ingress::level5 --rule rule5_level5 --match '{"ingress::scalars.metadata@node_id": {"value": "4"}, "ingress::scalars.metadata@isTrue": {"value": "1"}, "ing    ress::scalars.metadata@prevFeature": {"value": "10"}}' --action '{"type": "ingress::SetClass", "data": {"node_id": {"value": "5"}, "class": {"value": "0"}, "certainty": {"value": "100"}}}'
```

A su vez, hacemos que las llamadas a CheckFeature siempre pongan `meta.isTrue = 1`.

Agregamos los siguientes counters:
```
  695           meta.checked_feature = 0;
+ 696           if (meta.node_id == 0 && meta.isTrue == 1 && meta.prevFeature == 0){
+ 697             counter_.count(8);
+ 698           }
  699           level1.apply();
  700           if (meta.checked_feature == 1){
~ 701             counter_.count(9);
  702             meta.checked_feature = 0;
  703           }
  704           if (meta.class == CLASS_NOT_SET) {
+ 705             if (meta.node_id == 1 && meta.isTrue == 1 && meta.prevFeature == 9){
+ 706               counter_.count(10);
+ 707             }
  708             level2.apply();
  709             if (meta.checked_feature == 1){
~ 710               counter_.count(11);
  711               meta.checked_feature = 0;
  712             }
  713             if (meta.class == CLASS_NOT_SET) {
+ 714               if (meta.node_id == 2 && meta.isTrue == 1 && meta.prevFeature == 4){
+ 715                 counter_.count(12);
+ 716               }
  717               level3.apply();
  718               if (meta.checked_feature == 1){
~ 719                 counter_.count(13);
  720                 meta.checked_feature = 0;
  721               }
  722               if (meta.class == CLASS_NOT_SET) {
+ 723                 if (meta.node_id == 3 && meta.isTrue == 1 && meta.prevFeature == 1){
+ 724                   counter_.count(14);
+ 725                 }
  726                 level4.apply();
  727                 if (meta.checked_feature == 1){
~ 728                   counter_.count(15);
  729                   meta.checked_feature = 0;
  730                 }
  731                 if (meta.class == CLASS_NOT_SET) {
~ 732                   if (meta.node_id == 4 && meta.isTrue == 1 && meta.prevFeature == 10){
~_733                     counter_.count(16);
  734                   }
+ 735                   level5.apply();
  736                 }
  737               }
  738             }
  739           }
  ```

Es decir, como conocemos cuales son las reglas, sabemos a priori que valor deberían tener los metadatos para que hayan matches. Por ese motivo, antes de cada `leveln.apply()` sumamos a un counter, si los metadatos que ese apply debería matchear tienen los valores correctos. Y luego, al salir del apply, sumamos a un counter si efectivamante se ejecutó `CheckFeature()` en dicho apply.

El resultado es el siguiente:
| Counter | Value  |
|--|--|
| Total Packets | 30200 |
| TCP or UDP packets | 28900 |
| CheckFeature() | 55984 |
| SetClass() | 0 |
| Class == SEND_TO_ORACLE | 0 |
| Class == 0 | 0 |
| Class == 1 | 0 |
| Class Not Assigned | 908 |
| Los metadatos matchean con la regla de CheckFeature de level1 | 27992 |
| Ejecutó CheckFeature en level1.apply() | 27992 |
| Los metadatos matchean con la regla de CheckFeature de level2 | 27992 |
| Ejecutó CheckFeature en level2.apply() | 27992 |
| Los metadatos matchean con la regla de CheckFeature de level3 | 27992 |
| Ejecutó CheckFeature en level3.apply() | 0 |
| Los metadatos matchean con la regla de CheckFeature de level4 | 0 |
| Ejecutó CheckFeature en level4.apply() | 0 |
| Los metadatos matchean con la regla de SetClass de level5 | 0 |


Es evidente que el problema comienza en el nivel 3, donde a pesar de que los metadatos matchean con los que la regla requiere, la action no se ejecuta.
