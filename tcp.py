import asyncio
import os
from grader.tcputils import FLAGS_ACK, FLAGS_FIN, MSS, calc_checksum, fix_checksum, make_header, read_header
from tcputils import *
import math

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, ack_no)
            flags = FLAGS_SYN + FLAGS_ACK
            ack_no = seq_no + 1 # Número de bits no ack do servidor é o número de bits da 
                                # sequência recebida do cliente (seq_no) + o número de bits da mensagem (len(payload) provavelmente)
                                # Flag ack se refere à quantidade de informação recebida, seja pelo cliente, seja pelo servidor.
                                # Por exemplo, o servidor envia uma confirmação ao cliente informando que o próximo byte esperado 
                                # é o que está no valor ack.
            # O número de sequência (seq_no) se refere ao byte em que o servidor (ou cliente) está no seu envio de informações.
            
            self.rede.enviar(fix_checksum(make_header(dst_port, src_port, seq_no, ack_no, flags), src_addr, dst_addr), src_addr)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_no = seq_no
        self.ack_no = ack_no
        self.seq_envio = ack_no
        self.expected_seq_no = seq_no + 1
        self.callback = None
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

        src_addr, src_port, dst_addr, dst_port = self.id_conexao[0], self.id_conexao[1], \
             self.id_conexao[2], self.id_conexao[3] # Coleta informações de endereço

        #expected_seq_no = self.seq_no + 1

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.callback(self, b'')
            flags = FLAGS_ACK
            self.ack_no = seq_no + 1
            self.servidor.rede.enviar(fix_checksum(make_header(dst_port, \
                    src_port, self.seq_no, self.ack_no, flags), src_addr, \
                         dst_addr), src_addr)
        elif self.expected_seq_no == seq_no:
            dados = payload
            self.expected_seq_no += len(payload)
            self.ack_no = seq_no + len(payload)
            if len(dados) > 0:
                if (self.callback):
                    self.callback(self, dados)
                flags = FLAGS_ACK
                #print('estou enviando self.seq_no = ', self.seq_no, 'seq_no = ', seq_no, 'ack_no =', ack_no)
                self.servidor.rede.enviar(fix_checksum(make_header(dst_port, \
                    src_port, self.seq_no + 1, self.ack_no, flags), src_addr, \
                         dst_addr), src_addr)
        #print('recebido payload: %r' % payload)

        
    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.

        src_addr, src_port, dst_addr, dst_port = self.id_conexao[0], self.id_conexao[1], \
             self.id_conexao[2], self.id_conexao[3] # Coleta informações de endereço

        # Dividindo o payload em pacotes
        #self.seq_envio = max(self.seq_envio, self.ack_no)
        if len(dados) >= MSS:
            i = 0
            # aux = 0
            max_it = math.ceil((1.0*len(dados)) / MSS)
            # print('max_it = ', max_it)
            while i < max_it:
                # Preparando envio
                flags = FLAGS_ACK
                segment = make_header(dst_port, src_port, self.seq_no + 1, self.ack_no, flags)    
                # Enviando informações para o protocolo IP
                payload = dados[MSS*i:MSS*(i+1)]
                # print("enviando...", len(payload), i)
                self.servidor.rede.enviar(fix_checksum(segment + payload, src_addr, dst_addr), dst_addr)
                # atualiza o numero de sequencia
                self.seq_no += len(payload)
                i += 1
                # aux += len(payload)
        else: 
            # Preparando envio
            # print("amogus")
            flags = FLAGS_ACK
            segment = make_header(dst_port, src_port, self.seq_no + 1, self.ack_no, flags)    
            # Enviando informações para o protocolo IP
            self.servidor.rede.enviar(fix_checksum(segment + dados, src_addr, dst_addr), dst_addr)
            # atualiza o numero de sequencia
            self.seq_no += len(dados)

        # print('aux = ', aux, 'tam_dados = ', len(dados))
        

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão

        src_addr, src_port, dst_addr, dst_port = self.id_conexao[0], self.id_conexao[1], \
             self.id_conexao[2], self.id_conexao[3] # Coleta informações de endereço

        flags = FLAGS_FIN
        segment = make_header(dst_port, src_port, self.seq_no + 1, self.ack_no, flags)
        self.servidor.rede.enviar(fix_checksum(segment, src_addr, dst_addr), dst_addr)
        pass
