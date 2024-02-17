import socket
import ntcore
import subprocess
import itertools

from typing import List

IP_ADDRESS_FUNCTIONS = [
    lambda: list(itertools.dropwhile(lambda string: "eth0" not in string, str(subprocess.Popen(["ifconfig"], stdout=subprocess.PIPE).communicate()[0]).split("\\n")))[1].removeprefix("        inet ").split(" ")[0],
    lambda: ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET,socket.SOCK_DGRAM)]][0][1]])if l][0][0]),
    lambda: ((([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]),
]

def get_ip_address():
    for func in IP_ADDRESS_FUNCTIONS:
        try:
            output = func()
        except Exception as e:
            print(f"address function failed w/ error: {e}")
        if output:
            return output
    return "Could not get IP address :skull:"


def main():
    print( ip_address := get_ip_address() )
    TABLE_NAME = "jetson"
    TOPIC_NAME = "ip"
    NT_INSTANCE = ntcore.NetworkTableInstance.getDefault()
    NT_TABLE = NT_INSTANCE.getTable(TABLE_NAME)
    new_position_publisher = NewPositionPublisher(NT_TABLE, TOPIC_NAME)
    new_position_publisher(ip_address)


class NewPositionPublisher:
    def __init__(self, *, table, topic_name) -> None:
        self._publisher = table\
            .getDoubleArrayTopic(topic_name)\
            .publish()
    
    def __call__(self, value: List[float]) -> None:
        self._publisher.set(value)


if __name__ == "__main__":
    main()