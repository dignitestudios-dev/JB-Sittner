import React, { useContext, useEffect, useState } from "react";
import { IoMdArrowBack } from "react-icons/io";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { MyContext } from "../../context/GlobalContext";
import {
  collection,
  db,
  doc,
  getDocs,
  getDownloadURL,
  query,
  ref,
  storage,
  updateDoc,
  uploadBytesResumable,
  where,
} from "../../firbase/FirebaseInit";
import { toast } from "react-toastify";
import { FaEyeSlash, FaRegEye } from "react-icons/fa";

export default function EditMember() {
  const { Employee } = useContext(MyContext);
  const [contact, setContact] = useState({ value: "" });
  const location = useLocation();
  const [image, setImage] = useState();
  const [member, setMember] = useState({
    name: "",
    address: "",
    email: "",
    password: "",
    role: "user",
    id: "",
    pic: "",
    docId: "",
    role: "",
  });
  const [showPassword, setShowPassword] = useState(false);

  const navigate = useNavigate("");
  const re = /^[0-9\b]+$/;
  const handleChange = (e) => {
    const { value } = e.target;
    if (value === "" || re.test(value)) {
      setContact({ value });
    }
  };

  const getMemberRec = async () => {
    const employeesRef = collection(db, "employee");
    const employeeQuery = query(
      employeesRef,
      where("id", "==", location?.state?.id)
    );
    const querySnapshot = await getDocs(employeeQuery);
    const employeeData = querySnapshot.docs.map((doc) => ({
      docId: doc.id,
      ...doc.data(),
    }));
    setMember({
      name: employeeData[0].name,
      address: employeeData[0].address,
      email: employeeData[0].email,
      password: employeeData[0].password,
      pic: employeeData[0].pic,
      docId: employeeData[0].docId,
      id: employeeData[0].id,
      role: employeeData[0].role,
    });
    setContact({ value: employeeData[0]?.contact });
  };

  useEffect(() => {
    getMemberRec();
  }, []);

  const HandleInput = (e) => {
    const { name, value } = e.target;
    setMember({
      ...member,
      [name]: value,
    });
  };

  const UpdateEmp = async (e) => {
    e.preventDefault();
    const washingtonRef = doc(db, "employee", member?.docId);
    if (image) {
      const storageRef = ref(storage, `member/${member?.id}`);
      const uploadTask = uploadBytesResumable(storageRef, image);
      const myPromise = new Promise(async (resolve, reject) => {
        try {
          uploadTask.on(
            "state_changed",
            null,
            (error) => {
              reject(error.message);
            },
            async () => {
              const downloadURL = await getDownloadURL(uploadTask.snapshot.ref);
              await updateDoc(washingtonRef, {
                name: member?.name,
                email: member?.email,
                address: member?.address,
                pic: downloadURL,
                contact: contact?.value,
                password: member?.password,
              });
              resolve("Member Update");
            }
          );
        } catch (error) {
          reject(error.message);
        }
      });
      toast
        .promise(myPromise, {
          pending: "Updating member...",
          success: (data) => data,
          error: (error) => error,
        })
        .then(() => {
          Employee.role == "admin"
            ? navigate("/employee")
            : navigate("/profile", { state: { id: Employee?.id } });
        });
    } else {
      const myPromise = new Promise(async (resolve, reject) => {
        try {
          await updateDoc(washingtonRef, {
            name: member?.name,
            email: member?.email,
            address: member?.address,
            pic: member?.pic,
            contact: contact?.value,
            password: member?.password,
          });
          resolve("Member Update");
        } catch (error) {
          reject(error.message);
        }
      });
      toast
        .promise(myPromise, {
          pending: "Updating member...",
          success: (data) => data,
          error: (error) => error,
        })
        .then(() => {
          member.role == "admin"
            ? navigate("/admin")
            : member.role == "user"
            ? navigate("/employee")
            : navigate("/profile", { state: { id: Employee?.id } });
        });
    }
  };
  const [Preview, setPreview] = useState();
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
    <div class="bg-[#F7F7F7]  py-5 px-5 ">
      <NavLink
        to={`${member?.role == "admin" ? "/admin" : "/employee"}`}
        className="font-semibold text-[24px] leading-[29px] flex items-center"
      >
        {" "}
        <IoMdArrowBack size={25} className="mr-2" /> Edit Employee Profile
      </NavLink>

      <div class="bg-[#FFFFFF] border rounded-[10px] border-[#E4E4E4] mt-6 lg:py-10 lg:px-10">
        <div class="bg-[#F9FAFB] rounded-[10px] border border-[#E4E4E4] py-3 px-3 lg:py-10 lg:px-10">
          <div className="flex items-center">
            <div className="flex items-center">
              <div className="bg-[#94D0E4] flex rounded-[50%] items-center justify-center  w-[58px] h-[58px]">
                {Preview ? (
                  <img
                    src={Preview}
                    alt=""
                    className="w-[55px] h-[55px] rounded-full "
                    srcset=""
                  />
                ) : (
                  <img
                    src={member?.pic ? member?.pic : "/noprofile.png"}
                    class="cursor-pointer w-[58px] h-[58px]"
                    alt=""
                  />
                )}
              </div>
            </div>
            <label
              htmlFor="changeprofile"
              className="ml-3 font-semibold text-base underline cursor-pointer"
            >
              {" "}
              Change Photo
            </label>
            <input
              type="file"
              onChange={(e) => setImage(e.target.files[0])}
              className="hidden"
              id="changeprofile"
            />
          </div>
          <form onSubmit={(e) => UpdateEmp(e)}>
            <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
              <div className="mb-3">
                <label className="text-[13px] mb-1 font-semibold leading-[16.94px]">
                  Name
                </label>
                <input
                  type="text"
                  id="name-input"
                  name="name"
                  onChange={HandleInput}
                  value={member.name}
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
                  value={member.email}
                  className={`bg-white border border-gray-300 text-gray-900 text-sm rounded-lg h-[60px] mt-1 block w-full p-2.5 focus:outline-[#0A8A33] ${
                    Employee?.role == "admin" ? "" : "cursor-not-allowed"
                  } `}
                  required
                  disabled={Employee?.role == "admin" ? false : true}
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
                  value={member.address}
                  className="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg h-[60px] mt-1 block w-full p-2.5 focus:outline-[#0A8A33]"
                  required
                  placeholder="Address"
                />
              </div>
              {Employee?.role === "admin" && (
                <>
                  <div className="relative mb-3">
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
                </>
              )}
            </div>
            <div className="flex items-center gap-5">
              <button
                type="submit"
                className="text-white bg-[#0A8A33] rounded-lg w-[150px] h-[50px] px-5 py-2.5 text-center"
              >
                Update
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
