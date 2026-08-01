// wasi:sockets stand-ins for the transpiled parity runner: the exact shape
// the generated module destructures at instantiation, every member
// throwing on use. The preview2-shim browser build's sockets module
// predates the resource-class shape jco 0.5.x expects, and the parity
// runner never opens a socket, so these exist to satisfy instantiation
// only; the page's import map resolves
// `@bytecodealliance/preview2-shim/sockets` here.

const unavailable = (what) => {
  throw new Error(`wasi:sockets is not available in the browser (${what})`);
};

export class ResolveAddressStream {
  constructor() {
    unavailable("resolve-address-stream");
  }
}

export class Network {
  constructor() {
    unavailable("network");
  }
}

export class TcpSocket {
  constructor() {
    unavailable("tcp-socket");
  }
}

export class UdpSocket {
  constructor() {
    unavailable("udp-socket");
  }
}

export class IncomingDatagramStream {
  constructor() {
    unavailable("incoming-datagram-stream");
  }
}

export class OutgoingDatagramStream {
  constructor() {
    unavailable("outgoing-datagram-stream");
  }
}

export const instanceNetwork = {
  instanceNetwork: () => unavailable("instance-network"),
};

export const ipNameLookup = {
  ResolveAddressStream,
  resolveAddresses: () => unavailable("resolve-addresses"),
};

export const network = { Network };

export const tcp = { TcpSocket };

export const tcpCreateSocket = {
  createTcpSocket: () => unavailable("create-tcp-socket"),
};

export const udp = { UdpSocket, IncomingDatagramStream, OutgoingDatagramStream };

export const udpCreateSocket = {
  createUdpSocket: () => unavailable("create-udp-socket"),
};
