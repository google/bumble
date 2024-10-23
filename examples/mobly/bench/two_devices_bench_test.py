import time

from mobly import base_test
from mobly import test_runner
from mobly.controllers import android_device


class TwoDevicesBenchTest(base_test.BaseTestClass):
    def setup_class(self):
        self.ads = self.register_controller(android_device)
        self.dut1 = self.ads[0]
        self.dut1.load_snippet("bench", "com.github.google.bumble.btbench")
        self.dut2 = self.ads[1]
        self.dut2.load_snippet("bench", "com.github.google.bumble.btbench")

    def test_rfcomm_client_send_receive(self):
        print("### Starting Receiver")
        receiver = self.dut2.bench.runRfcommServer("receive")
        receiver_id = receiver["id"]
        print("--- Receiver status:", receiver)
        while not receiver["model"]["running"]:
            print("--- Waiting for Receiver to be running...")
            time.sleep(1)
            receiver = self.dut2.bench.getRunner(receiver_id)

        print("### Starting Sender")
        sender = self.dut1.bench.runRfcommClient(
            "send", "DC:E5:5B:E5:51:2C", 100, 970, 100
        )
        print("--- Sender status:", sender)

        print("--- Waiting for Sender to complete...")
        sender_result = self.dut1.bench.waitForRunnerCompletion(sender["id"])
        print("--- Sender result:", sender_result)


if __name__ == "__main__":
    test_runner.main()
