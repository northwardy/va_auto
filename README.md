# va_auto
Este script irá criar um arquivo .csv com os resultados obtidos nos scans de vulnerabilidades realizado no Nessus. Procedimento completo para o procedimento de gestão de vulnerabilidades está disponível no documento "Procedimento de Gestão de Vulnerabilidades - xxx". 
Para executar é necessário: 

1 - Baixar Python 2.7.x
https://www.python.org/downloads/

2 - Baixar a lib "xlrd" para o script funcionar corretamente
pip install xlrd

3 - Baixar o script "va.py" disponibilizado neste projeto

4 - Baixar os arquivos .nessus e copiá-los para a pasta do projeto

5 - Entrar na pasta do projeto e executar:
python2.7 ./va.py

Será gerado um arquivo csv denomidado "Vulnerabilidades.csv".
