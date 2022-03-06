import asyncio
import time
from grader.tcputils import FLAGS_ACK, FLAGS_FIN, MSS, calc_checksum, fix_checksum, make_header, read_header
from tcputils import *
import math

ALPHA = 0.125
BETA = 0.25


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
        self.sendbase = 0
        self.start = 0
        self.end = 0
        self.reenvio = False
        self.sampleRTT = 0
        self.estimatedRTT = -1
        self.devRTT = -1
        self.timeoutInterval = 0
        self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._exemplo_timer)
        self.timer.cancel()
        self.pending_segments = []

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        src_addr, src_port, dst_addr, dst_port = self.id_conexao[0], self.id_conexao[1], \
             self.id_conexao[2], self.id_conexao[3] # Coleta informações de endereço

        if len(self.pending_segments) > 0:
            self.servidor.rede.enviar(fix_checksum(self.pending_segments[0], src_addr, dst_addr), src_addr)
            self.reenvio = True
            #self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)
        

    def _set_timer_info(self, segment):
        self.pending_segments.append(segment)


    def _calc_rtt(self):
        if self.start > 0:
            self.end = time.time()
            print('recv: ', self.end)
            connect_ack = True if self.sampleRTT == 0 else False
            self.sampleRTT = self.end - self.start
            print('sampleRTT = ', self.sampleRTT)

            if connect_ack:
                self.estimatedRTT = self.sampleRTT
                self.devRTT = self.sampleRTT/2
            else: 
                self.estimatedRTT = (1 - ALPHA)*self.estimatedRTT + ALPHA*self.sampleRTT
                self.devRTT = (1 - BETA)*self.devRTT + BETA*abs(self.sampleRTT - self.estimatedRTT)
            self.timeoutInterval = self.estimatedRTT + 4.0*self.devRTT

            print('estimatedRTT = ', self.estimatedRTT)
            print('devRTT = ', self.devRTT)
            print('timeoutInterval = ', self.timeoutInterval)
            print('-------------------')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

        src_addr, src_port, dst_addr, dst_port = self.id_conexao[0], self.id_conexao[1], \
             self.id_conexao[2], self.id_conexao[3] # Coleta informações de endereço
        
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.callback(self, b'')
            flags = FLAGS_ACK
            self.ack_no = seq_no + 1
            self.servidor.rede.enviar(fix_checksum(make_header(dst_port, \
                    src_port, self.seq_no, self.ack_no, flags), src_addr, \
                         dst_addr), src_addr)
        elif self.expected_seq_no == seq_no:
            self.reenvio = False
            dados = payload
            self.expected_seq_no += len(payload)
            self.ack_no = seq_no + len(payload)
            if len(dados) > 0:
                if (self.callback):
                    self.callback(self, dados)
                flags = FLAGS_ACK
                self.servidor.rede.enviar(fix_checksum(make_header(dst_port, \
                    src_port, self.seq_no + 1, self.ack_no, flags), src_addr, \
                         dst_addr), src_addr)
             
            if ack_no > self.sendbase:
                if not self.reenvio:
                    self._calc_rtt()
                self.sendbase = ack_no
                if len(self.pending_segments) > 0:
                    self.pending_segments.pop(0)
                    self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._exemplo_timer)
                else:
                    self.timer.cancel()
                    

        
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
        if len(dados) >= MSS:
            i = 0
            max_it = math.ceil((1.0*len(dados)) / MSS)
            self.sendbase = self.seq_no + 1
            while i < max_it:
                # Preparando envio
                flags = FLAGS_ACK
                segment = make_header(dst_port, src_port, self.seq_no + 1, self.ack_no, flags)    
                # Enviando informações para o protocolo IP
                payload = dados[MSS*i:MSS*(i+1)]
                self.servidor.rede.enviar(fix_checksum(segment + payload, src_addr, dst_addr), dst_addr)
                if not self.reenvio:
                    self.start = time.time()
                # armazena os segmentos
                self._set_timer_info(segment + payload)
                # atualiza o numero de sequencia
                self.seq_no += len(payload)
                i += 1
            print('sent: ', self.start)
            if (not self.timer) or (self.timer and self.timer.cancelled()):
                self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._exemplo_timer)
        else: 
            # Preparando envio
            flags = FLAGS_ACK
            segment = make_header(dst_port, src_port, self.seq_no + 1, self.ack_no, flags)    
            payload = b''
            # Enviando informações para o protocolo IP
            self.servidor.rede.enviar(fix_checksum(segment + dados, src_addr, dst_addr), dst_addr)
            if not self.reenvio:
                self.start = time.time()
            print('sent: ', self.start)
            
            # Inicializa o timer para retransmissao
            if (not self.timer) or (self.timer and self.timer.cancelled()):
                self._set_timer_info(segment + payload)
                self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._exemplo_timer)
            # atualiza o numero de sequencia
            self.seq_no += len(dados)
        

        

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
