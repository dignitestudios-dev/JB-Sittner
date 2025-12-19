import React, { useContext, useEffect, useState } from "react";
import LeftImage from "../../components/Auth/LeftImage";
import OtpCom from "../../components/Auth/OtpInput";
import { NavLink, useNavigate } from "react-router-dom";
import { MyContext } from "../../context/GlobalContext";
import { toast } from "react-toastify";

export default function Otp() {
  const {
    OtpVal,
    Otp,
    setOtp,
    ForgetEmail,
    setOtpVal,
    setLoader,
    loader,
    setForgetToken,
    ForgetToken,
  } = useContext(MyContext);

  const navigate = useNavigate("");

  useEffect(() => {
    if (ForgetEmail == "") {
      navigate("/forgotpassword");
    }
  }, []);

  const HandleSubmit = async () => {
    try {
      const res = await fetch(
        "https://us-central1-jbst-dispatch-app-b62fd.cloudfunctions.net/verifyOTP",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            token: ForgetToken, // token from sendOTP
            otp: OtpVal, // user input
          }),
        }
      );

      const data = await res.json();

      if (res.ok && data.success) {
        setOtp(""); // clear OTP
        setForgetToken(""); // clear token
        navigate("/updatepassword");
      } else {
        toast.error(data.error || "Wrong OTP");
      }
    } catch (error) {
      console.error(error);
      toast.error("Verification failed");
    }
  };
  const [timer, setTimer] = useState(60);
  useEffect(() => {
    let intervalId;
    if (timer > 0) {
      intervalId = setInterval(() => {
        setTimer((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(intervalId);
  }, [timer]);

  useEffect(() => {
    const timer = setTimeout(() => {
      setOtp("");
    }, 120000);
    return () => clearTimeout(timer);
  }, [timer]);

  const ResendOTP = async (e) => {
    e.preventDefault();
    setTimer(60);
    const toastId = toast.loading("Resending OTP...");

    try {
      const res = await fetch(
        "https://us-central1-jbst-dispatch-app-b62fd.cloudfunctions.net/sendOTP",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email: ForgetEmail }),
        }
      );

      const data = await res.json();

      if (res.ok) {
        setOtp(data.otp);
        setToken(data.token); // update token for new OTP
        toast.update(toastId, {
          render: "OTP resent successfully!",
          type: "success",
          isLoading: false,
          autoClose: 3000,
        });
      } else {
        toast.update(toastId, {
          render: data.error || "Failed to resend OTP",
          type: "error",
          isLoading: false,
          autoClose: 3000,
        });
      }
    } catch (error) {
      console.error(error);
      toast.update(toastId, {
        render: "An error occurred",
        type: "error",
        isLoading: false,
        autoClose: 3000,
      });
    }
  };

  return (
    <div className="grid sm:grid-cols-1 h-screen lg:grid-cols-2 p-3   md:py-10 md:px-10 gap-4 flex items-center ">
      <div className="h-full">
        <LeftImage />
      </div>
      <div className="">
        <div className="flex items-center flex-col mb-4">
          <img src="/logo.webp" className="mb-3 w-[150px]" alt="" />
          <h2 className="mb-3 font-bold text-[32px] leading-[38px]">
            Verification
          </h2>
          <p className="mb-3 font-medium text-base leading-[19px] text-center">
            Please enter the code that we sent to your email <br />{" "}
            <span className="font-bold"> {ForgetEmail},</span> to reset your
            password.
          </p>
        </div>
        <OtpCom />
        <p className="mt-6 text-center text-[#8A8A8A] text-base font-medium ">
          Didn’t receive the code?{" "}
          <button
            className="bg-transparent"
            style={{
              cursor: timer > 0 ? "not-allowed" : "pointer",
              color: timer > 0 ? "#0A8A33" : "#0A8A33",
              opacity: timer > 0 ? "0.5" : "1",
            }}
            disabled={timer > 0 ? true : false}
            onClick={ResendOTP}
          >
            {" "}
            Resend now{" "}
          </button>
          <span className="text-[#0A8A33] "> {timer > 0 && timer} </span>
        </p>
        <div className="mt-6 flex justify-center">
          <button
            onClick={HandleSubmit}
            className="text-white bg-[#0A8A33] lg:w-[370px] rounded-lg    px-5 py-2.5 text-center"
          >
            Next
          </button>
        </div>

        <div className="flex items-center justify-center mt-6">
          <NavLink
            to={"/forgotpassword"}
            className="flex items-center hover:text-[#0A8A33]"
          >
            <img src="/back.webp" width={20} alt="" />
            <span class="ml-1 text-base font-normal ">Back</span>
          </NavLink>
        </div>
      </div>
    </div>
  );
}
