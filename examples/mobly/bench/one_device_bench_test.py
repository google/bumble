from mobly import base_test
from mobly import test_runner
from mobly.controllers import android_device


class OneDeviceBenchTest(base_test.BaseTestClass):

    def setup_class(self):
        self.ads = self.register_controller(android_device)
        self.dut = self.ads[0]
        self.dut.load_snippet("bench", "com.github.google.bumble.btbench")

    def test_rfcomm_client_ping(self):
        runner = self.dut.bench.runRfcommClient(
            "ping", "DC:E5:5B:E5:51:2C", 100, 970, 100
        )
        print("### Initial status:", runner)
        final_status = self.dut.bench.waitForRunnerCompletion(runner["id"])
        print("### Final status:", final_status)

    def test_rfcomm_client_send(self):
        runner = self.dut.bench.runRfcommClient(
            "send", "DC:E5:5B:E5:51:2C", 100, 970, 0
        )
        print("### Initial status:", runner)
        final_status = self.dut.bench.waitForRunnerCompletion(runner["id"])
        print("### Final status:", final_status)

    def test_l2cap_client_ping(self):
        runner = self.dut.bench.runL2capClient(
            "ping", "4B:2A:67:76:2B:E3", 128, True, 100, 970, 100, "HIGH"
        )
        print("### Initial status:", runner)
        final_status = self.dut.bench.waitForRunnerCompletion(runner["id"])
        print("### Final status:", final_status)

    def test_l2cap_client_send(self):
        runner = self.dut.bench.runL2capClient(
            "send",
            "F1:F1:F1:F1:F1:F1",
            128,
            True,
            100,
            970,
            0,
            "HIGH",
            10000,
        )
        print("### Initial status:", runner)
        final_status = self.dut.bench.waitForRunnerCompletion(runner["id"])
        print("### Final status:", final_status)

    def test_gatt_client_send(self):
        runner = self.dut.bench.runGattClient(
            "send", "F1:F1:F1:F1:F1:F1", 128, True, 100, 970, 100, "HIGH"
        )
        print("### Initial status:", runner)
        final_status = self.dut.bench.waitForRunnerCompletion(runner["id"])
        print("### Final status:", final_status)

    def test_gatt_server_receive(self):
        runner = self.dut.bench.runGattServer("receive")
        print("### Initial status:", runner)
        final_status = self.dut.bench.waitForRunnerCompletion(runner["id"])
        print("### Final status:", final_status)


if __name__ == "__main__":
    test_runner.main()
