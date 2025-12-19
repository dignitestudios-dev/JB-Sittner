import React, { useEffect, useState } from "react";
import { IoMdArrowBack } from "react-icons/io";
import { IoMdPerson } from "react-icons/io";
import { NavLink, useNavigate } from "react-router-dom";
import {
  addDoc,
  auth,
  collection,
  createUserWithEmailAndPassword,
  db,
  getDocs,
  getDownloadURL,
  query,
  ref,
  signInWithEmailAndPassword,
  storage,
  uploadBytesResumable,
  where,
} from "../../firbase/FirebaseInit";
import { toast } from "react-toastify";
import Cookies from "js-cookie";
import { FaEyeSlash, FaRegEye } from "react-icons/fa";

export default function AddMember() {
  const navigate = useNavigate("");
  const [contact, setContact] = useState({ value: "" });
  const [image, setImage] = useState();
  const [Preview, setPreview] = useState();
  const [showPassword, setShowPassword] = useState(false);
  const [member, setMember] = useState({
    name: "",
    address: "",
    email: "",
    password: "",
    role: "user",
  });

  const re = /^[0-9\b]+$/;
  const handleChange = (e) => {
    const { value } = e.target;
    if (value === "" || re.test(value)) {
      setContact({ value });
    }
  };

  const HandleInput = (e) => {
    const { name, value } = e.target;
    setMember({
      ...member,
      [name]: value,
    });
  };

  const generateUniqueId = async () => {
    const randomId = Math.floor(100000 + Math.random() * 900000).toString();
    const existingEmployee = await getDocs(
      query(collection(db, "employee"), where("id", "==", randomId))
    );

    if (!existingEmployee.empty) {
      return generateUniqueId();
    }
    return randomId;
  };

  const handleAddMember = async (e) => {
    e.preventDefault();
    const currentUser = JSON.parse(Cookies.get("employe"));
    if (member?.password.length < 6) {
      return toast("Password must be at least 6 characters");
    }

    if (contact.value?.length < 10) {
      return toast("Contact must be at least 10 characters");
    }
    if (contact.value?.length > 11) {
      return toast("Contact must not be more than 11 characters");
    }

    const existingEmployeeByEmail = await getDocs(
      query(collection(db, "employee"), where("email", "==", member?.email))
    );
    const existingEmployeeByNumber = await getDocs(
      query(collection(db, "employee"), where("contact", "==", contact.value))
    );
    if (!existingEmployeeByEmail.empty) {
      return toast("Email is already in use");
    } else if (!existingEmployeeByNumber.empty) {
      return toast("Number is already in use");
    } else {
      const myPromise = new Promise(async (resolve, reject) => {
        try {
          const uniqueId = await generateUniqueId();
          const storageRef = ref(storage, `member/${uniqueId}`);
          const uploadTask = uploadBytesResumable(storageRef, image);

          uploadTask.on(
            "state_changed",
            null,
            (error) => {
              reject(error.message);
            },
            async () => {
              // Once upload is complete, get the download URL
              try {
                const downloadURL = await getDownloadURL(
                  uploadTask.snapshot.ref
                );

                // Convert to Mountain Time Zone (MST/MDT)
                const options = {
                  timeZone: "America/Denver",
                  year: "numeric",
                  month: "2-digit",
                  day: "2-digit",
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                  hour12: true,
                };
                const formatter = new Intl.DateTimeFormat("en-US", options);
                const createdAtMountainTime = formatter.format(new Date());

                // Adding the new document
                await addDoc(collection(db, "employee"), {
                  contact: contact.value,
                  address: member?.address,
                  email: member?.email,
                  name: member?.name,
                  password: member?.password,
                  role: member?.role,
                  id: uniqueId,
                  createdat: createdAtMountainTime,
                  pic: image ? downloadURL : "",
                });

                resolve("Member Created");
              } catch (error) {
                reject(error.message);
              }
            }
          );
        } catch (error) {
          reject(error.message);
        }
      });

      toast
        .promise(myPromise, {
          pending: "Adding member...",
          success: (data) => data,
          error: (error) => error,
        })
        .then(() => {
          navigate("/employee");
        });
    }
  };

  useEffect(() => {
    if (!image) {
      setPreview(undefined);
      return;
    }
    const objectUrl = URL.createObjectURL(image);
    setPreview(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [image]);

  return (
    <div class="bg-[#F7F7F7] h-[80vh] py-5 px-5 ">
      <NavLink
        to={"/employee"}
        className="font-semibold text-[24px] leading-[29px] flex items-center"
      >
        {" "}
        <IoMdArrowBack size={25} className="mr-2" /> Add New Member
      </NavLink>

      <div class="bg-[#FFFFFF] border rounded-[10px] border-[#E4E4E4] mt-6 lg:py-10 lg:px-10">
        <div class="bg-[#F9FAFB] rounded-[10px] border border-[#E4E4E4] py-3 px-3 lg:py-10 lg:px-10">
          <div className="flex items-center">
            <div className="w-[60px] h-[60px] rounded-full border border-dashed border-[#0A8A33] flex items-center justify-center">
              {Preview ? (
                <img
                  src={Preview}
                  alt=""
                  className="w-[55px] h-[55px] rounded-full "
                  srcset=""
                />
              ) : (
                <IoMdPerson color="#0A8A33" size={25} />
              )}
            </div>
            <label
              htmlFor="changeprofile"
              className="ml-3 font-semibold text-base underline cursor-pointer"
            >
              {" "}
              Upload Photo
            </label>
            <input
              type="file"
              className="hidden"
              onChange={(e) => setImage(e.target.files[0])}
              id="changeprofile"
            />
          </div>
          <form onSubmit={(e) => handleAddMember(e)}>
            <div className="mt-5 lg:grid grid-cols-1 gap-5 lg:grid-cols-2">
              <div className=" mb-3">
                <label className="text-[13px] mb-1 font-semibold leading-[16.94px]">
                  Name
                </label>
                <input
                  type="text"
                  id="name-input"
                  name="name"
                  onChange={HandleInput}
                  className="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg h-[60px] mt-1 block w-full p-2.5 focus:outline-[#0A8A33]"
                  required
                  placeholder="Full Name"
                />
              </div>
              <div className="mb-3">
                <label className="text-[13px] mb-1 font-semibold leading-[16.94px]">
                  Email
                </label>
                <input
                  type="email"
                  id="email-input"
                  name="email"
                  onChange={HandleInput}
                  className="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg h-[60px] mt-1 block w-full p-2.5 focus:outline-[#0A8A33]"
                  required
                  placeholder="Email Address"
                />
              </div>
              <div className="mb-3">
                <label className="text-[13px] mb-1 font-semibold leading-[16.94px]">
                  Contact No
                </label>
                <input
                  type="tel"
                  id="contact-input"
                  onChange={handleChange}
                  value={contact.value}
                  className="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg h-[60px] mt-1 block w-full p-2.5 focus:outline-[#0A8A33]"
                  required
                  placeholder="Contact No"
                />
              </div>
              <div className="mb-3">
                <label className="text-[13px] mb-1 font-semibold leading-[16.94px]">
                  Address
                </label>
                <input
                  type="text"
                  id="address-input"
                  name="address"
                  onChange={HandleInput}
                  className="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg h-[60px] mt-1 block w-full p-2.5 focus:outline-[#0A8A33]"
                  required
                  placeholder="Address"
                />
              </div>
              <div className="relative mb-3 col-span-2 lg:col-span-1">
                <label className="text-[13px] mb-1 font-semibold leading-[16.94px]">
                  Password
                </label>
                <input
                  type={showPassword ? "text" : "password"}
                  id="password-input"
                  name="password"
                  onChange={HandleInput}
                  value={member.password}
                  className="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg   block w-full p-2.5 focus:outline-[#0A8A33] "
                  required
                  placeholder="Password"
                />
                <div className="absolute inset-y-0 end-0 top-5 flex items-center  pe-3.5 ">
                  {showPassword ? (
                    <div onClick={() => setShowPassword(!showPassword)}>
                      <FaRegEye className="text-gray-400 cursor-pointer" />
                    </div>
                  ) : (
                    <div onClick={() => setShowPassword(!showPassword)}>
                      {" "}
                      <FaEyeSlash className="text-gray-400 cursor-pointer" />
                    </div>
                  )}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-5 mt-5">
              <button
                type="submit"
                className="text-white bg-[#0A8A33] rounded-lg w-[150px] h-[50px] px-5 py-2.5 text-center"
              >
                Save
              </button>
              <NavLink
                to={"/employee"}
                className="bg-[#F1F1F1] font-bold rounded-lg w-[150px] h-[50px] px-5 py-2.5 text-center"
              >
                Cancel
              </NavLink>
            </div>
          </form>
        </div>
        <div></div>
      </div>
    </div>
  );
}
