from scapy.all import ARP, Ether, srp
import netifaces

# Autor: Juan Felipe Ibañez Ferreira
# Descrição: Scanner de Rede para identificar dispositivos ativos via ARP

def obter_ip_rede():
    """
    Obtém automaticamente a rede do dispositivo.
    Retorna o IP da rede no formato CIDR (ex: 192.168.1.1/24).
    """
    interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    endereco_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    mascara = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
    
    # Converte a máscara de rede para a notação CIDR
    bits_mascara = sum(bin(int(x)).count('1') for x in mascara.split('.'))
    return f"{endereco_ip}/{bits_mascara}"

def escanear_rede(rede):
    """
    Realiza um scan ARP na rede informada para identificar dispositivos ativos.
    Retorna uma lista de dicionários contendo IPs e MACs dos dispositivos.
    """
    print("Enviando pacotes ARP para descobrir dispositivos...")
    
    # Criando pacote ARP e encapsulando em um pacote Ethernet
    pacote_arp = ARP(pdst=rede)
    pacote_ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pacote = pacote_ether / pacote_arp
    
    # Enviando pacotes e coletando respostas
    respostas, _ = srp(pacote, timeout=2, verbose=False)
    
    dispositivos = []
    for resposta in respostas:
        dispositivos.append({
            'IP': resposta[1].psrc,
            'MAC': resposta[1].hwsrc
        })
    
    return dispositivos

if __name__ == "__main__":
    print("Obtendo a rede automaticamente...")
    rede = obter_ip_rede()
    print(f"Escaneando a rede: {rede}\n")
    
    dispositivos_encontrados = escanear_rede(rede)
    
    if dispositivos_encontrados:
        print("Dispositivos encontrados:")
        for dispositivo in dispositivos_encontrados:
            print(f"IP: {dispositivo['IP']}, MAC: {dispositivo['MAC']}")
    else:
        print("Nenhum dispositivo encontrado.")
    
    print("Scan finalizado com sucesso!")
